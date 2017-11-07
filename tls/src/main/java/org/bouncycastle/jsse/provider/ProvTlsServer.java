package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLException;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jsse.BCSNIMatcher;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.ClientCertificateType;
import org.bouncycastle.tls.CompressionMethod;
import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.ServerNameList;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsDHUtils;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JceDefaultTlsCredentialedAgreement;
import org.bouncycastle.tls.crypto.impl.jcajce.JceDefaultTlsCredentialedDecryptor;

class ProvTlsServer
    extends DefaultTlsServer
    implements ProvTlsPeer
{
    private static Logger LOG = Logger.getLogger(ProvTlsServer.class.getName());

    private static final int provEphemeralDHKeySize = PropertyUtils.getIntegerSystemProperty("jdk.tls.ephemeralDHKeySize", 2048, 1024, 8192);

    protected final ProvTlsManager manager;
    protected final ProvSSLParameters sslParameters;

    protected ProvSSLSessionImpl sslSession = null;
    protected BCSNIServerName matchedSNIServerName = null;
    protected Set<String> keyManagerMissCache = null;
    protected TlsCredentials credentials = null;
    protected boolean handshakeComplete = false;

    ProvTlsServer(ProvTlsManager manager) throws SSLException
    {
        super(manager.getContextData().getCrypto());

        this.manager = manager;
        this.sslParameters = manager.getProvSSLParameters();

        if (!manager.getEnableSessionCreation())
        {
            throw new SSLException("Session resumption not implemented yet and session creation is disabled");
        }
    }

    @Override
    protected int getMaximumNegotiableCurveBits()
    {
        // NOTE: BC supports all the current set of point formats so we don't check them here

        return SupportedGroups.getServerMaximumNegotiableCurveBits(manager.getContext().isFips(), clientSupportedGroups);
    }

    @Override
    protected int getMaximumNegotiableFiniteFieldBits()
    {
        int maxBits = SupportedGroups.getServerMaximumNegotiableFiniteFieldBits(manager.getContext().isFips(), clientSupportedGroups);

        return maxBits >= provEphemeralDHKeySize ? maxBits : 0;
    }

    @Override
    protected boolean selectCipherSuite(int cipherSuite) throws IOException
    {
        if (!selectCredentials(cipherSuite))
        {
            return false;
        }

        manager.getContext().validateNegotiatedCipherSuite(cipherSuite);

        return super.selectCipherSuite(cipherSuite);
    }

    @Override
    protected int selectCurve(int minimumCurveBits)
    {
        if (clientSupportedGroups == null)
        {
            return selectDefaultCurve(minimumCurveBits);
        }

        boolean isFips = manager.getContext().isFips();

        return SupportedGroups.getServerSelectedCurve(isFips, minimumCurveBits, clientSupportedGroups);
    }

    @Override
    protected int selectDefaultCurve(int minimumCurveBits)
    {
        return SupportedGroups.getServerDefaultCurve(manager.getContext().isFips(), minimumCurveBits);
    }

    @Override
    protected TlsDHConfig selectDefaultDHConfig(int minimumFiniteFieldBits)
    {
        return SupportedGroups.getServerDefaultDHConfig(manager.getContext().isFips(), minimumFiniteFieldBits);
    }

    @Override
    protected TlsDHConfig selectDHConfig(int minimumFiniteFieldBits)
    {
        minimumFiniteFieldBits = Math.max(minimumFiniteFieldBits, provEphemeralDHKeySize);

        if (clientSupportedGroups == null)
        {
            return selectDefaultDHConfig(minimumFiniteFieldBits);
        }

        boolean isFips = manager.getContext().isFips();

        int namedGroup = SupportedGroups.getServerSelectedFiniteField(isFips, minimumFiniteFieldBits,
            clientSupportedGroups);

        return TlsDHUtils.createNamedDHConfig(namedGroup);
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
    public int[] getCipherSuites()
    {
        return TlsUtils.getSupportedCipherSuites(manager.getContextData().getCrypto(),
            manager.getContext().convertCipherSuites(sslParameters.getCipherSuites()));
    }

    @Override
    protected short[] getCompressionMethods()
    {
        return manager.getContext().isFips()
            ?   new short[]{ CompressionMethod._null }
            :   super.getCompressionMethods();
    }

//  public TlsKeyExchange getKeyExchange() throws IOException
//  {
//      // TODO[jsse] Check that all key exchanges used in JSSE supportedCipherSuites are handled
//      return super.getKeyExchange();
//  }

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
        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(serverVersion))
        {
            serverSigAlgs = JsseUtils.getSupportedSignatureAlgorithms(getCrypto());
        }

        Vector certificateAuthorities = new Vector();
        X509TrustManager tm = manager.getContextData().getTrustManager();
        if (tm != null)
        {
            for (X509Certificate caCert : tm.getAcceptedIssuers())
            {
                certificateAuthorities.addElement(X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded()));
            }
        }

        return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
    }

    @Override
    public int getSelectedCipherSuite() throws IOException
    {
        keyManagerMissCache = new HashSet<String>();

        int selectedCipherSuite = super.getSelectedCipherSuite();

        LOG.fine("Server selected cipher suite: " + manager.getContext().getCipherSuiteString(selectedCipherSuite));

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
        if (matchedSNIServerName != null)
        {
            checkServerExtensions().put(TlsExtensionsUtils.EXT_server_name, TlsExtensionsUtils.createEmptyExtensionData());
        }

        return serverExtensions;
    }

    @Override
    public TlsSession getSessionToResume(byte[] sessionID)
    {
        ProvSSLSessionContext sessionContext = manager.getContextData().getServerSessionContext();
        this.sslSession = sessionContext.getSessionImpl(sessionID);

        if (sslSession != null)
        {
            TlsSession sessionToResume = sslSession.getTlsSession();
            if (sessionToResume != null)
            {
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
        /*
         * TODO[jsse] It may be best to just require the "protocols" list to be a contiguous set
         * (especially in light of TLS_FALLBACK_SCSV), then just determine the minimum/maximum,
         * and keep the super class implementation of this. 
         */
        String[] protocols = sslParameters.getProtocols();
        if (protocols != null && protocols.length > 0)
        {
            for (ProtocolVersion version = clientVersion; version != null; version = version.getPreviousVersion())
            {
                String versionString = manager.getContext().getProtocolString(version);
                if (versionString != null && JsseUtils.contains(protocols, versionString))
                {
                    LOG.fine("Server selected protocol version: " + version);
                    return serverVersion = version;
                }
            }
        }
        throw new TlsFatalAlert(AlertDescription.protocol_version);
    }

    @Override
    public void notifyClientCertificate(Certificate clientCertificate) throws IOException
    {
        // NOTE: This method isn't called unless we returned non-null from getCertificateRequest() earlier
        assert sslParameters.getNeedClientAuth() || sslParameters.getWantClientAuth();

        boolean noClientCert = clientCertificate == null || clientCertificate.isEmpty();
        if (noClientCert)
        {
            if (sslParameters.getNeedClientAuth())
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
        }
        else
        {
            X509Certificate[] chain = JsseUtils.getX509CertificateChain(manager.getContextData().getCrypto(), clientCertificate);
            short clientCertificateType = clientCertificate.getCertificateAt(0).getClientCertificateType();
            String authType = JsseUtils.getAuthTypeClient(clientCertificateType);

            if (!manager.isClientTrusted(chain, authType))
            {
                /*
                 * TODO[jsse] The low-level TLS API currently doesn't provide a way to indicate that
                 * we wish to proceed with an untrusted client certificate, so we always fail here.
                 */
                throw new TlsFatalAlert(AlertDescription.bad_certificate);
            }
        }
    }

    @Override
    public synchronized void notifyHandshakeComplete() throws IOException
    {
        this.handshakeComplete = true;

        TlsSession handshakeSession = context.getSession();

        if (sslSession == null || sslSession.getTlsSession() != handshakeSession)
        {
            sslSession = manager.getContextData().getServerSessionContext().reportSession(handshakeSession, null, -1);
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

        if (clientExtensions != null)
        {
            /*
             * TODO[jsse] RFC 6066 A server that implements this extension MUST NOT accept the
             * request to resume the session if the server_name extension contains a different name.
             */
            Collection<BCSNIMatcher> sniMatchers = manager.getProvSSLParameters().getSNIMatchers();
            if (sniMatchers != null && !sniMatchers.isEmpty())
            {
                ServerNameList serverNameList = TlsExtensionsUtils.getServerNameExtension(clientExtensions);
                if (serverNameList != null)
                {
                    matchedSNIServerName = JsseUtils.findMatchingSNIServerName(serverNameList, sniMatchers);
                    if (matchedSNIServerName == null)
                    {
                        throw new TlsFatalAlert(AlertDescription.unrecognized_name);
                    }
                }
            }
        }
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

        case KeyExchangeAlgorithm.DH_DSS:
        case KeyExchangeAlgorithm.DH_RSA:
        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_RSA:
        case KeyExchangeAlgorithm.ECDH_ECDSA:
        case KeyExchangeAlgorithm.ECDH_RSA:
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
        case KeyExchangeAlgorithm.RSA:
            break;

        default:
            return false;
        }

        X509KeyManager km = manager.getContextData().getKeyManager();
        if (km == null)
        {
            return false;
        }

        String keyType = JsseUtils.getAuthTypeServer(keyExchangeAlgorithm);
        if (keyManagerMissCache.contains(keyType))
        {
            return false;
        }

        // TODO[jsse] Is there some extension where the client can specify these (SNI maybe)?
        Principal[] issuers = null;
        // TODO[jsse] How is this used?
        Socket socket = null;

        String alias = km.chooseServerAlias(keyType, issuers, socket);
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

        PrivateKey privateKey = km.getPrivateKey(alias);
        Certificate certificate = JsseUtils.getCertificateMessage(crypto, km.getCertificateChain(alias));

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
        case KeyExchangeAlgorithm.DH_DSS:
        case KeyExchangeAlgorithm.DH_RSA:
        case KeyExchangeAlgorithm.ECDH_ECDSA:
        case KeyExchangeAlgorithm.ECDH_RSA:
        {
            // TODO[jsse] Need to have TlsCrypto construct the credentials from the certs/key
            this.credentials = new JceDefaultTlsCredentialedAgreement((JcaTlsCrypto)crypto, certificate, privateKey);
            return true;
        }

        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_RSA:
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
        {
            short signatureAlgorithm = TlsUtils.getSignatureAlgorithm(keyExchangeAlgorithm);
            SignatureAndHashAlgorithm sigAlg = TlsUtils.chooseSignatureAndHashAlgorithm(context,
                supportedSignatureAlgorithms, signatureAlgorithm);

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
