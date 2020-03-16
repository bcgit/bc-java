package org.bouncycastle.jsse.provider;

import java.io.IOException;
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
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jsse.BCSNIMatcher;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.jsse.BCX509ExtendedTrustManager;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
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
import org.bouncycastle.tls.ServerName;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;

class ProvTlsServer
    extends DefaultTlsServer
    implements ProvTlsPeer
{
    private static final Logger LOG = Logger.getLogger(ProvTlsServer.class.getName());

    private static final int provEphemeralDHKeySize = PropertyUtils.getIntegerSystemProperty("jdk.tls.ephemeralDHKeySize", 2048, 1024, 8192);

    protected final ProvTlsManager manager;
    protected final ProvSSLParameters sslParameters;
    protected final JsseSecurityParameters jsseSecurityParameters = new JsseSecurityParameters();

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
        return SupportedGroups.getServerMaximumNegotiableCurveBits(manager.getContextData().getContext().isFips(),
            clientSupportedGroups);
    }

    @Override
    protected int getMaximumNegotiableFiniteFieldBits()
    {
        int[] clientSupportedGroups = context.getSecurityParametersHandshake().getClientSupportedGroups();
        int maxBits = SupportedGroups.getServerMaximumNegotiableFiniteFieldBits(
            manager.getContextData().getContext().isFips(), clientSupportedGroups);
        return maxBits >= provEphemeralDHKeySize ? maxBits : 0;
    }

    @Override
    protected Vector<ProtocolName> getProtocolNames()
    {
        return JsseUtils.getProtocolNames(sslParameters.getApplicationProtocols());
    }

    @Override
    protected int[] getSupportedCipherSuites()
    {
        return manager.getContextData().getContext().getActiveCipherSuites(getCrypto(), sslParameters,
            getProtocolVersions());
    }

    @Override
    protected ProtocolVersion[] getSupportedVersions()
    {
        return manager.getContextData().getContext().getActiveProtocolVersions(sslParameters);
    }

    @Override
    protected boolean preferLocalCipherSuites()
    {
        return sslParameters.getUseCipherSuitesOrder();
    }

    @Override
    protected boolean selectCipherSuite(int cipherSuite) throws IOException
    {
        TlsCredentials cipherSuiteCredentials = selectCredentials(cipherSuite);

        if (null == cipherSuiteCredentials)
        {
            String cipherSuiteName = ProvSSLContextSpi.getCipherSuiteName(cipherSuite);
            LOG.finer("Server found no credentials for cipher suite: " + cipherSuiteName);
            return false;
        }

        boolean result = super.selectCipherSuite(cipherSuite);
        if (result)
        {
            this.credentials = cipherSuiteCredentials;
        }
        return result;
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

        return SupportedGroups.getServerSelectedFiniteField(getCrypto(), manager.getContextData().getContext().isFips(),
            minimumFiniteFieldBits, clientSupportedGroups);
    }

    @Override
    protected int selectDHDefault(int minimumFiniteFieldBits)
    {
        return SupportedGroups.getServerDefaultDH(manager.getContextData().getContext().isFips(),
            minimumFiniteFieldBits);
    }

    @Override
    protected int selectECDH(int minimumCurveBits)
    {
        int[] clientSupportedGroups = context.getSecurityParametersHandshake().getClientSupportedGroups();
        if (clientSupportedGroups == null)
        {
            return selectECDHDefault(minimumCurveBits);
        }

        return SupportedGroups.getServerSelectedCurve(getCrypto(), manager.getContextData().getContext().isFips(),
            minimumCurveBits, clientSupportedGroups);
    }

    @Override
    protected int selectECDHDefault(int minimumCurveBits)
    {
        return SupportedGroups.getServerDefaultECDH(manager.getContextData().getContext().isFips(), minimumCurveBits);
    }

    @Override
    protected ProtocolName selectProtocolName() throws IOException
    {
        if (null == sslParameters.getEngineAPSelector() && null == sslParameters.getSocketAPSelector())
        {
            return super.selectProtocolName();
        }

        @SuppressWarnings("unchecked")
        Vector<ProtocolName> applicationProtocols = clientProtocolNames;

        List<String> protocols = JsseUtils.getProtocolNames(applicationProtocols);
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

    @Override
    public boolean allowLegacyResumption()
    {
        return JsseUtils.allowLegacyResumption();
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

        final ContextData contextData = manager.getContextData();

        // TODO[jsse] These should really be based on TlsCrypto support
        short[] certificateTypes = new short[]{ ClientCertificateType.ecdsa_sign,
            ClientCertificateType.rsa_sign, ClientCertificateType.dss_sign };

        Vector<SignatureAndHashAlgorithm> serverSigAlgs = null;

        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(context.getServerVersion()))
        {
            // TODO[tls13] CertificateRequest can contain distinct serverSigAlgsCert

            List<SignatureSchemeInfo> signatureSchemes = contextData.getActiveSignatureSchemes(sslParameters,
                new ProtocolVersion[]{ context.getServerVersion() });

            // TODO[tls13] Legacy schemes (cert-only for TLS 1.3) complicate this 
            jsseSecurityParameters.localSigSchemes = signatureSchemes;
            jsseSecurityParameters.localSigSchemesCert = signatureSchemes;

            serverSigAlgs = contextData.getSignatureAndHashAlgorithms(signatureSchemes);
        }

        Vector<X500Name> certificateAuthorities = null;
        {
            Set<X500Principal> caSubjects = new HashSet<X500Principal>();

            BCX509ExtendedTrustManager x509TrustManager = contextData.getX509TrustManager();
            for (X509Certificate caCert : x509TrustManager.getAcceptedIssuers())
            {
                caSubjects.add(caCert.getSubjectX500Principal());
            }

            if (!caSubjects.isEmpty())
            {
                certificateAuthorities = new Vector<X500Name>(caSubjects.size());
                for (X500Principal caSubject : caSubjects)
                {
                    certificateAuthorities.add(X500Name.getInstance(caSubject.getEncoded()));
                }
            }
        }

        return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
    }

    @Override
    public JcaTlsCrypto getCrypto()
    {
        return manager.getContextData().getCrypto();
    }

    @Override
    public int getSelectedCipherSuite() throws IOException
    {
        final ContextData contextData = manager.getContextData();
        final SecurityParameters securityParameters = context.getSecurityParametersHandshake();

        /*
         * TODO[jsse] Ideally, setting the handshake session would be done in getSessionToResume, but
         * that is currently never called.
         */
        {
            ProvSSLSessionContext sslSessionContext = contextData.getServerSessionContext();
            String peerHost = manager.getPeerHost();
            int peerPort = manager.getPeerPort();

            ProvSSLSessionHandshake handshakeSession;
            if (null == sslSession)
            {
                handshakeSession = new ProvSSLSessionHandshake(sslSessionContext, peerHost, peerPort,
                    securityParameters, jsseSecurityParameters);
            }
            else
            {
                handshakeSession = new ProvSSLSessionResumed(sslSessionContext, peerHost, peerPort, securityParameters,
                    jsseSecurityParameters, sslSession.getTlsSession(), sslSession.getJsseSessionParameters());
            }

            manager.notifyHandshakeSession(handshakeSession);
        }

        // Setup the peer supported signature schemes  
        {
            @SuppressWarnings("unchecked")
            Vector<SignatureAndHashAlgorithm> clientSigAlgs = (Vector<SignatureAndHashAlgorithm>)
                securityParameters.getClientSigAlgs();
            @SuppressWarnings("unchecked")
            Vector<SignatureAndHashAlgorithm> clientSigAlgsCert = (Vector<SignatureAndHashAlgorithm>)
                securityParameters.getClientSigAlgsCert();

            // TODO[tls13] Legacy schemes (cert-only for TLS 1.3) complicate these conversions 
            jsseSecurityParameters.peerSigSchemes = contextData.getSignatureSchemes(clientSigAlgs);
            jsseSecurityParameters.peerSigSchemesCert = (clientSigAlgs == clientSigAlgsCert)
                ?   jsseSecurityParameters.peerSigSchemes
                :   contextData.getSignatureSchemes(clientSigAlgsCert);
        }

        if (DummyX509KeyManager.INSTANCE == contextData.getX509KeyManager())
        {
            // We don't support anonymous cipher suites, so there has to be a (real) key manager
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        keyManagerMissCache = new HashSet<String>();

        int selectedCipherSuite = super.getSelectedCipherSuite();

        keyManagerMissCache = null;

        String selectedCipherSuiteName = manager.getContextData().getContext()
            .validateNegotiatedCipherSuite(sslParameters, selectedCipherSuite);

        LOG.fine("Server selected cipher suite: " + selectedCipherSuiteName);

        return selectedCipherSuite;
    }

    @Override
    public Hashtable<Integer, byte[]> getServerExtensions() throws IOException
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

        @SuppressWarnings("unchecked")
        Hashtable<Integer, byte[]> result = serverExtensions;

        return result;
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

        String serverVersionName = manager.getContextData().getContext().validateNegotiatedProtocol(sslParameters,
            serverVersion);

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

            TlsCertificate ee = clientCertificate.getCertificateAt(0);

            /*
             * TODO[jsse] Need a less kludgy approach here, or maybe we only need a dummy value for
             * 'authType' anyway?
             */
            short signatureAlgorithm;
            if (ee.supportsSignatureAlgorithm(SignatureAlgorithm.ed25519))
            {
                signatureAlgorithm = SignatureAlgorithm.ed25519;
            }
            else if (ee.supportsSignatureAlgorithm(SignatureAlgorithm.ed448))
            {
                signatureAlgorithm = SignatureAlgorithm.ed448;
            }
            else
            {
                signatureAlgorithm = ee.getLegacySignatureAlgorithm();
            }

            if (signatureAlgorithm < 0)
            {
                throw new TlsFatalAlert(AlertDescription.unsupported_certificate);
            }

            String authType = JsseUtils.getAuthTypeClient(signatureAlgorithm);

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
    public void processClientExtensions(@SuppressWarnings("rawtypes") Hashtable clientExtensions) throws IOException
    {
        super.processClientExtensions(clientExtensions);

        /*
         * TODO[jsse] RFC 6066 A server that implements this extension MUST NOT accept the
         * request to resume the session if the server_name extension contains a different name.
         */

        @SuppressWarnings("unchecked")
        Vector<ServerName> serverNameList = context.getSecurityParametersHandshake().getClientServerNames();
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

    @Override
    public boolean requiresExtendedMasterSecret()
    {
        return !JsseUtils.allowLegacyMasterSecret();
    }

    @Override
    public boolean shouldUseExtendedMasterSecret()
    {
        return JsseUtils.useExtendedMasterSecret();
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

    protected TlsCredentials selectCredentials(int cipherSuite) throws IOException
    {
        int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(cipherSuite);
        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_RSA:
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
        case KeyExchangeAlgorithm.NULL:
        case KeyExchangeAlgorithm.RSA:
        {
            if (KeyExchangeAlgorithm.RSA == keyExchangeAlgorithm
                || !TlsUtils.isSignatureAlgorithmsExtensionAllowed(context.getServerVersion()))
            {
                return selectServerCredentialsLegacy(keyExchangeAlgorithm);
            }

            return selectServerCredentials(keyExchangeAlgorithm);
        }

        default:
            return null;
        }
    }

    protected TlsCredentials selectServerCredentials(int keyExchangeAlgorithm) throws IOException
    {
        BCAlgorithmConstraints algorithmConstraints = sslParameters.getAlgorithmConstraints();

        final short legacySignatureAlgorithm = TlsUtils.getLegacySignatureAlgorithmServer(keyExchangeAlgorithm);

        for (SignatureSchemeInfo signatureSchemeInfo : jsseSecurityParameters.peerSigSchemes)
        {
            if (!TlsUtils.isValidSignatureSchemeForServerKeyExchange(signatureSchemeInfo.getSignatureScheme(),
                keyExchangeAlgorithm))
            {
                continue;
            }

            final short signatureAlgorithm = signatureSchemeInfo.getSignatureAlgorithm();

            /*
             * TODO[jsse] Probably insufficient for rsa_pss_* signature algorithms. In fact we'd
             * prefer that none of the legacy names shadow the signature scheme key algorithms
             * (maybe rename them to e.g. "KE_RSA" etc.?), to avoid this conditional.
             */
            String keyType = (legacySignatureAlgorithm == signatureAlgorithm)
                ?   JsseUtils.getKeyTypeLegacyServer(keyExchangeAlgorithm)
                :   JsseUtils.getKeyType(signatureSchemeInfo);

            if (keyManagerMissCache.contains(keyType))
            {
                continue;
            }

            if (!signatureSchemeInfo.isActive(algorithmConstraints))
            {
                continue;
            }

            ProvX509Key x509Key = manager.chooseServerKey(keyType, null);
            if (null == x509Key
                || !JsseUtils.isUsableKeyForServer(signatureAlgorithm, x509Key.getPrivateKey()))
            {
                keyManagerMissCache.add(keyType);
                continue;
            }

            return JsseUtils.createCredentialedSigner(context, getCrypto(), x509Key,
                signatureSchemeInfo.getSignatureAndHashAlgorithm());
        }

        return null;
    }

    protected TlsCredentials selectServerCredentialsLegacy(int keyExchangeAlgorithm) throws IOException
    {
        String keyType = JsseUtils.getKeyTypeLegacyServer(keyExchangeAlgorithm);
        if (keyManagerMissCache.contains(keyType))
        {
            return null;
        }

        ProvX509Key x509Key = manager.chooseServerKey(keyType, null);
        if (null == x509Key
            || !JsseUtils.isUsableKeyForServerLegacy(keyExchangeAlgorithm, x509Key.getPrivateKey()))
        {
            keyManagerMissCache.add(keyType);
            return null;
        }

        if (KeyExchangeAlgorithm.RSA == keyExchangeAlgorithm)
        {
            return JsseUtils.createCredentialedDecryptor(getCrypto(), x509Key);
        }

        return JsseUtils.createCredentialedSigner(context, getCrypto(), x509Key, null);
    }
}
