package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLException;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jsse.BCSNIMatcher;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.jsse.BCX509ExtendedTrustManager;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.ClientCertificateType;
import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JceDefaultTlsCredentialedDecryptor;

class ProvTlsServer
    extends DefaultTlsServer
    implements ProvTlsPeer
{
    private static final Logger LOG = Logger.getLogger(ProvTlsServer.class.getName());

    private static final int provEphemeralDHKeySize = PropertyUtils.getIntegerSystemProperty("jdk.tls.ephemeralDHKeySize", 2048, 1024, 8192);

    protected final ProvTlsManager manager;
    protected final ProvSSLParameters sslParameters;

    protected ProvSSLSession sslSession = null;
    protected BCSNIServerName matchedSNIServerName = null;
    protected Set<String> keyManagerMissCache = null;
    protected TlsCredentials credentials = null;
    protected boolean handshakeComplete = false;

    ProvTlsServer(ProvTlsManager manager, ProvSSLParameters sslParameters) throws SSLException
    {
        super(manager.getContextData().getCrypto());

        this.manager = manager;
        this.sslParameters = sslParameters.copyForConnection();

        if (!manager.getEnableSessionCreation())
        {
            throw new SSLException("Session resumption not implemented yet and session creation is disabled");
        }
    }

    @Override
    protected boolean allowCertificateStatus()
    {
        return false;
    }

    @Override
    protected int getMaximumNegotiableCurveBits()
    {
        int[] clientSupportedGroups = context.getSecurityParametersHandshake().getClientSupportedGroups();
        return SupportedGroups.getServerMaximumNegotiableCurveBits(manager.getContext().isFips(), clientSupportedGroups);
    }

    @Override
    protected int getMaximumNegotiableFiniteFieldBits()
    {
        int[] clientSupportedGroups = context.getSecurityParametersHandshake().getClientSupportedGroups();
        int maxBits = SupportedGroups.getServerMaximumNegotiableFiniteFieldBits(manager.getContext().isFips(), clientSupportedGroups);
        return maxBits >= provEphemeralDHKeySize ? maxBits : 0;
    }

    @Override
    protected Vector getProtocolNames()
    {
        return JsseUtils.getProtocolNames(sslParameters.getApplicationProtocols());
    }

    @Override
    protected int[] getSupportedCipherSuites()
    {
        return manager.getContext().getActiveCipherSuites(getCrypto(), sslParameters, getProtocolVersions());
    }

    @Override
    protected ProtocolVersion[] getSupportedVersions()
    {
        return manager.getContext().getActiveProtocolVersions(sslParameters);
    }

    @Override
    protected boolean preferLocalCipherSuites()
    {
        return sslParameters.getUseCipherSuitesOrder();
    }

    @Override
    protected boolean selectCipherSuite(int cipherSuite) throws IOException
    {
        if (!selectCredentials(cipherSuite))
        {
            String cipherSuiteName = ProvSSLContextSpi.getCipherSuiteName(cipherSuite);
            LOG.finer("Server found no credentials for cipher suite: " + cipherSuiteName);
            return false;
        }

        manager.getContext().validateNegotiatedCipherSuite(sslParameters, cipherSuite);

        return super.selectCipherSuite(cipherSuite);
    }

    @Override
    protected int selectDH(int minimumFiniteFieldBits)
    {
        minimumFiniteFieldBits = Math.max(minimumFiniteFieldBits, provEphemeralDHKeySize);

        int[] clientSupportedGroups = context.getSecurityParametersHandshake().getClientSupportedGroups();
        if (clientSupportedGroups == null)
        {
            return selectDHDefault(minimumFiniteFieldBits);
        }

        return SupportedGroups.getServerSelectedFiniteField(getCrypto(), manager.getContext().isFips(),
            minimumFiniteFieldBits, clientSupportedGroups);
    }

    @Override
    protected int selectDHDefault(int minimumFiniteFieldBits)
    {
        return SupportedGroups.getServerDefaultDH(manager.getContext().isFips(), minimumFiniteFieldBits);
    }

    @Override
    protected int selectECDH(int minimumCurveBits)
    {
        int[] clientSupportedGroups = context.getSecurityParametersHandshake().getClientSupportedGroups();
        if (clientSupportedGroups == null)
        {
            return selectECDHDefault(minimumCurveBits);
        }

        return SupportedGroups.getServerSelectedCurve(getCrypto(), manager.getContext().isFips(), minimumCurveBits,
            clientSupportedGroups);
    }

    @Override
    protected int selectECDHDefault(int minimumCurveBits)
    {
        return SupportedGroups.getServerDefaultECDH(manager.getContext().isFips(), minimumCurveBits);
    }

    @Override
    protected ProtocolName selectProtocolName() throws IOException
    {
        if (null == sslParameters.getEngineAPSelector() && null == sslParameters.getSocketAPSelector())
        {
            return super.selectProtocolName();
        }

        List<String> protocols = JsseUtils.getProtocolNames(clientProtocolNames);
        String protocol = manager.selectApplicationProtocol(Collections.unmodifiableList(protocols));
        if (null == protocol)
        {
            throw new TlsFatalAlert(AlertDescription.no_application_protocol);
        }
        else if (protocol.length() < 1)
        {
            return null;
        }
        else if (!protocols.contains(protocol))
        {
            throw new TlsFatalAlert(AlertDescription.no_application_protocol);
        }

        return ProtocolName.asUtf8Encoding(protocol);
    }

    @Override
    protected boolean shouldSelectProtocolNameEarly()
    {
        return null == sslParameters.getEngineAPSelector() && null == sslParameters.getSocketAPSelector();
    }

    public synchronized boolean isHandshakeComplete()
    {
        return handshakeComplete;
    }

    @Override
    public TlsCredentials getCredentials()
        throws IOException
    {
        return credentials;
    }

    @Override
    public CertificateRequest getCertificateRequest() throws IOException
    {
        boolean shouldRequest = sslParameters.getNeedClientAuth() || sslParameters.getWantClientAuth();
        if (!shouldRequest)
        {
            return null;
        }

        short[] certificateTypes = new short[]{ ClientCertificateType.rsa_sign,
            ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign };

        Vector serverSigAlgs = null;
        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(context.getServerVersion()))
        {
            serverSigAlgs = JsseUtils.getSupportedSignatureAlgorithms(getCrypto());
        }

        Vector certificateAuthorities = null;
        {
            Set<X500Principal> caSubjects = new HashSet<X500Principal>();

            BCX509ExtendedTrustManager x509TrustManager = manager.getContextData().getX509TrustManager();
            for (X509Certificate caCert : x509TrustManager.getAcceptedIssuers())
            {
                caSubjects.add(caCert.getSubjectX500Principal());
            }

            if (!caSubjects.isEmpty())
            {
                certificateAuthorities = new Vector(caSubjects.size());
                for (X500Principal caSubject : caSubjects)
                {
                    certificateAuthorities.addElement(X500Name.getInstance(caSubject.getEncoded()));
                }
            }
        }

        return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
    }

    @Override
    public int getSelectedCipherSuite() throws IOException
    {
        /*
         * TODO[jsse] Ideally, setting the handshake session would be done in getSessionToResume, but
         * that is currently never called.
         */
        {
            ProvSSLSessionContext sslSessionContext = manager.getContextData().getServerSessionContext();
            String peerHost = manager.getPeerHost();
            int peerPort = manager.getPeerPort();
            SecurityParameters securityParameters = context.getSecurityParametersHandshake();

            ProvSSLSessionHandshake handshakeSession;
            if (null == sslSession)
            {
                handshakeSession = new ProvSSLSessionHandshake(sslSessionContext, peerHost, peerPort, securityParameters);
            }
            else
            {
                handshakeSession = new ProvSSLSessionResumed(sslSessionContext, peerHost, peerPort, securityParameters,
                    sslSession.getTlsSession(), sslSession.getJsseSessionParameters());
            }

            manager.notifyHandshakeSession(handshakeSession);
        }

        keyManagerMissCache = new HashSet<String>();

        int selectedCipherSuite = super.getSelectedCipherSuite();
        String selectedCipherSuiteName = ProvSSLContextSpi.getCipherSuiteName(selectedCipherSuite);

        LOG.fine("Server selected cipher suite: " + selectedCipherSuiteName);

        keyManagerMissCache = null;

        return selectedCipherSuite;
    }

    @Override
    public Hashtable getServerExtensions() throws IOException
    {
        super.getServerExtensions();

        /*
         * TODO[jsse] RFC 6066 When resuming a session, the server MUST NOT include a server_name
         * extension in the server hello.
         */
        if (null != matchedSNIServerName)
        {
            TlsExtensionsUtils.addServerNameExtensionServer(checkServerExtensions());
        }

        return serverExtensions;
    }

    @Override
    public TlsSession getSessionToResume(byte[] sessionID)
    {
        ProvSSLSessionContext sslSessionContext = manager.getContextData().getServerSessionContext();
        ProvSSLSession availableSSLSession = sslSessionContext.getSessionImpl(sessionID);

        if (null != availableSSLSession)
        {
            TlsSession sessionToResume = availableSSLSession.getTlsSession();
            if (null != sessionToResume && isResumable(availableSSLSession))
            {
                this.sslSession = availableSSLSession;
                return sessionToResume;
            }
        }

        if (!manager.getEnableSessionCreation())
        {
            throw new IllegalStateException("No resumable sessions and session creation is disabled");
        }

        return null;
    }

    @Override
    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        Level level = alertLevel == AlertLevel.warning                      ? Level.FINE
                    : alertDescription == AlertDescription.internal_error   ? Level.WARNING
                    :                                                         Level.INFO;

        if (LOG.isLoggable(level))
        {
            String msg = JsseUtils.getAlertLogMessage("Server raised", alertLevel, alertDescription);
            if (message != null)
            {
                msg = msg + ": " + message;
            }

            LOG.log(level, msg, cause);
        }
    }

    @Override
    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
        super.notifyAlertReceived(alertLevel, alertDescription);

        Level level = alertLevel == AlertLevel.warning  ? Level.FINE
                    :                                     Level.INFO;

        if (LOG.isLoggable(level))
        {
            String msg = JsseUtils.getAlertLogMessage("Server received", alertLevel, alertDescription);

            LOG.log(level, msg);
        }
    }

    @Override
    public ProtocolVersion getServerVersion() throws IOException
    {
        ProtocolVersion serverVersion = super.getServerVersion();

        manager.getContext().validateNegotiatedProtocol(sslParameters, serverVersion);

        String serverVersionName = ProvSSLContextSpi.getProtocolVersionName(serverVersion);

        LOG.fine("Server selected protocol version: " + serverVersionName);

        return serverVersion;
    }

    @Override
    public void notifyClientCertificate(Certificate clientCertificate) throws IOException
    {
        // NOTE: This method isn't called unless we returned non-null from getCertificateRequest() earlier
        if (!sslParameters.getNeedClientAuth() && !sslParameters.getWantClientAuth())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (null == clientCertificate || clientCertificate.isEmpty())
        {
            if (sslParameters.getNeedClientAuth())
            {
                short alertDescription = TlsUtils.isTLSv13(context)
                    ?   AlertDescription.certificate_required
                    :   AlertDescription.handshake_failure;

                throw new TlsFatalAlert(alertDescription);
            }
        }
        else
        {
            X509Certificate[] chain = JsseUtils.getX509CertificateChain(getCrypto(), clientCertificate);
            short signatureAlgorithm = clientCertificate.getCertificateAt(0).getLegacySignatureAlgorithm();
            String authType = JsseUtils.getAuthStringClient(signatureAlgorithm);

            // NOTE: We never try to continue the handshake with an untrusted client certificate
            manager.checkClientTrusted(chain, authType);
        }
    }

    @Override
    public synchronized void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        this.handshakeComplete = true;

        TlsSession connectionTlsSession = context.getSession();

        if (null == sslSession || sslSession.getTlsSession() != connectionTlsSession)
        {
            ProvSSLSessionContext sslSessionContext = manager.getContextData().getServerSessionContext();
            String peerHost = manager.getPeerHost();
            int peerPort = manager.getPeerPort();
            JsseSessionParameters jsseSessionParameters = new JsseSessionParameters(
                sslParameters.getEndpointIdentificationAlgorithm());

            this.sslSession = sslSessionContext.reportSession(peerHost, peerPort, connectionTlsSession,
                jsseSessionParameters);
        }

        manager.notifyHandshakeComplete(new ProvSSLConnection(context, sslSession));
    }

    @Override
    public void notifySecureRenegotiation(boolean secureRenegotiation) throws IOException
    {
        if (!secureRenegotiation)
        {
            boolean allowLegacyHelloMessages = PropertyUtils.getBooleanSystemProperty("sun.security.ssl.allowLegacyHelloMessages", true);
            if (!allowLegacyHelloMessages)
            {
                /*
                 * RFC 5746 3.4/3.6. In this case, some clients/servers may want to terminate the handshake instead
                 * of continuing; see Section 4.1/4.3 for discussion.
                 */
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
        }
    }

    @Override
    public void processClientExtensions(Hashtable clientExtensions) throws IOException
    {
        super.processClientExtensions(clientExtensions);

        /*
         * TODO[jsse] RFC 6066 A server that implements this extension MUST NOT accept the
         * request to resume the session if the server_name extension contains a different name.
         */
        Vector serverNameList = context.getSecurityParametersHandshake().getClientServerNames();
        if (null != serverNameList)
        {
            Collection<BCSNIMatcher> sniMatchers = sslParameters.getSNIMatchers();
            if (null == sniMatchers || sniMatchers.isEmpty())
            {
                LOG.fine("Server ignored SNI (no matchers specified)");
            }
            else
            {
                this.matchedSNIServerName = JsseUtils.findMatchingSNIServerName(serverNameList, sniMatchers);
                if (null == matchedSNIServerName)
                {
                    throw new TlsFatalAlert(AlertDescription.unrecognized_name);
                }

                LOG.fine("Server accepted SNI: " + matchedSNIServerName);
            }
        }
    }

    protected boolean isResumable(ProvSSLSession availableSSLSession)
    {
        /*
         * TODO[jsse] - Note that session resumption is not yet implemented in the low-level TLS layer anyway.
         * 
         * Checks that will need to be done here before this can return true:
         * - endpoint ID algorithm consistency
         * - SNI consistency
         */
        return false;
    }

    protected boolean selectCredentials(int cipherSuite) throws IOException
    {
        this.credentials = null;

        int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(cipherSuite);
        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DH_anon:
        case KeyExchangeAlgorithm.ECDH_anon:
            return true;

        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_RSA:
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
        case KeyExchangeAlgorithm.RSA:
            break;

        default:
            return false;
        }

        String keyType = JsseUtils.getAuthTypeServer(keyExchangeAlgorithm);
        if (keyManagerMissCache.contains(keyType))
        {
            return false;
        }

        // TODO[jsse] Is there some extension where the client can specify these (SNI maybe)?
        Principal[] issuers = null;

        String alias = manager.chooseServerAlias(keyType, issuers);
        if (alias == null)
        {
            keyManagerMissCache.add(keyType);
            return false;
        }

        TlsCrypto crypto = getCrypto();
        if (!(crypto instanceof JcaTlsCrypto))
        {
            // TODO[jsse] Need to have TlsCrypto construct the credentials from the certs/key
            throw new UnsupportedOperationException();
        }

        X509ExtendedKeyManager x509KeyManager = manager.getContextData().getX509KeyManager();
        PrivateKey privateKey = x509KeyManager.getPrivateKey(alias);
        Certificate certificate = JsseUtils.getCertificateMessage(crypto, x509KeyManager.getCertificateChain(alias));

        if (privateKey == null
            || !JsseUtils.isUsableKeyForServer(keyExchangeAlgorithm, privateKey)
            || certificate.isEmpty())
        {
            keyManagerMissCache.add(keyType);
            return false;
        }

        /*
         * TODO[jsse] Before proceeding with EC credentials, should we check (TLS 1.2+) that the
         * used curve is supported by the client according to the elliptic_curves/named_groups
         * extension?
         */
        
        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_RSA:
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
        {
            short signatureAlgorithm = TlsUtils.getLegacySignatureAlgorithmServer(keyExchangeAlgorithm);
            SignatureAndHashAlgorithm sigAlg = TlsUtils.chooseSignatureAndHashAlgorithm(context,
                context.getSecurityParametersHandshake().getClientSigAlgs(), signatureAlgorithm);

            // TODO[jsse] Need to have TlsCrypto construct the credentials from the certs/key
            this.credentials = new JcaDefaultTlsCredentialedSigner(new TlsCryptoParameters(context), (JcaTlsCrypto)crypto,
                privateKey, certificate, sigAlg);
            return true;
        }

        case KeyExchangeAlgorithm.RSA:
        {
            // TODO[jsse] Need to have TlsCrypto construct the credentials from the certs/key
            this.credentials = new JceDefaultTlsCredentialedDecryptor((JcaTlsCrypto)crypto, certificate, privateKey);
            return true;
        }

        default:
            return false;
        }
    }
}
