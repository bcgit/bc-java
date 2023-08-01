package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.jsse.BCX509Key;
import org.bouncycastle.jsse.provider.SignatureSchemeInfo.PerConnection;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.CertificateStatusRequest;
import org.bouncycastle.tls.CertificateStatusRequestItemV2;
import org.bouncycastle.tls.CertificateStatusType;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.IdentifierType;
import org.bouncycastle.tls.OCSPStatusRequest;
import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.ServerName;
import org.bouncycastle.tls.SessionParameters;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsDHGroupVerifier;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.TrustedAuthority;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.IPAddress;
import org.bouncycastle.util.encoders.Hex;

class ProvTlsClient
    extends DefaultTlsClient
    implements ProvTlsPeer
{
    private static final Logger LOG = Logger.getLogger(ProvTlsClient.class.getName());

    private static final boolean provClientEnableCA = PropertyUtils
        .getBooleanSystemProperty("jdk.tls.client.enableCAExtension", false);

    private static final boolean provClientEnableSessionResumption = PropertyUtils
        .getBooleanSystemProperty("org.bouncycastle.jsse.client.enableSessionResumption", true);

    private static final boolean provClientEnableStatusRequest = PropertyUtils
        .getBooleanSystemProperty("jdk.tls.client.enableStatusRequestExtension", true);

    private static final boolean provClientEnableTrustedCAKeys = PropertyUtils
        .getBooleanSystemProperty("org.bouncycastle.jsse.client.enableTrustedCAKeysExtension", false);

    private static final boolean provClientOmitSigAlgsCert = PropertyUtils
        .getBooleanSystemProperty("org.bouncycastle.jsse.client.omitSigAlgsCertExtension", true);

    private static final boolean provEnableSNIExtension = PropertyUtils
        .getBooleanSystemProperty("jsse.enableSNIExtension", true);

    protected final String clientID;
    protected final ProvTlsManager manager;
    protected final ProvSSLParameters sslParameters;
    protected final JsseSecurityParameters jsseSecurityParameters = new JsseSecurityParameters();

    protected ProvSSLSession sslSession = null;
    protected boolean handshakeComplete = false;

    ProvTlsClient(ProvTlsManager manager, ProvSSLParameters sslParameters)
    {
        super(manager.getContextData().getCrypto());

        this.clientID = JsseUtils.getPeerID("client", manager);
        this.manager = manager;
        this.sslParameters = sslParameters.copyForConnection();
    }

    public String getID()
    {
        return clientID;
    }

    public ProvSSLSession getSession()
    {
        return sslSession;
    }

    public TlsContext getTlsContext()
    {
        return context;
    }

    @Override
    protected Vector<X500Name> getCertificateAuthorities()
    {
        if (provClientEnableCA)
        {
            /*
             * TODO[tls13] Avoid fetching the CAs more than once if this method and
             * getTrustedCAIndication are both called.
             */
            return JsseUtils.getCertificateAuthorities(manager.getContextData().getX509TrustManager());
        }

        return null;
    }

    @Override
    protected CertificateStatusRequest getCertificateStatusRequest()
    {
        if (!provClientEnableStatusRequest)
        {
            return null;
        }

        // JSSE API provides no way to specify responders or extensions, so use default request
        OCSPStatusRequest ocspStatusRequest = new OCSPStatusRequest(null, null);

        return new CertificateStatusRequest(CertificateStatusType.ocsp, ocspStatusRequest);
    }

    @Override
    protected Vector<CertificateStatusRequestItemV2> getMultiCertStatusRequest()
    {
        if (!provClientEnableStatusRequest)
        {
            return null;
        }

        // JSSE API provides no way to specify responders or extensions, so use default request
        OCSPStatusRequest ocspStatusRequest = new OCSPStatusRequest(null, null);

        Vector<CertificateStatusRequestItemV2> result = new Vector<CertificateStatusRequestItemV2>(2);
        result.add(new CertificateStatusRequestItemV2(CertificateStatusType.ocsp_multi, ocspStatusRequest));
        result.add(new CertificateStatusRequestItemV2(CertificateStatusType.ocsp, ocspStatusRequest));
        return result;
    }

    @Override
    protected Vector<ProtocolName> getProtocolNames()
    {
        return JsseUtils.getProtocolNames(sslParameters.getApplicationProtocols());
    }

    @Override
    protected Vector<Integer> getSupportedGroups(@SuppressWarnings("rawtypes") Vector namedGroupRolesRaw)
    {
        // NOTE: Ignore roles; BCJSSE determines supported groups BEFORE signature schemes and cipher suites  
//        @SuppressWarnings("unchecked")
//        Vector<Integer> namedGroupRoles = namedGroupRolesRaw;

        return NamedGroupInfo.getSupportedGroupsLocalClient(jsseSecurityParameters.namedGroups);
    }

    @Override
    protected Vector<ServerName> getSNIServerNames()
    {
        if (provEnableSNIExtension)
        {
            List<BCSNIServerName> sniServerNames = sslParameters.getServerNames();
            if (null == sniServerNames)
            {
                String peerHostSNI = manager.getPeerHostSNI();

                /*
                 * TODO[jsse] Consider removing the restriction that the name must contain a '.'
                 * character, which is currently there for compatibility with SunJSSE.
                 */
                if (null != peerHostSNI && peerHostSNI.indexOf('.') > 0 && !IPAddress.isValid(peerHostSNI))
                {
                    try
                    {
                        sniServerNames = Collections.<BCSNIServerName>singletonList(new BCSNIHostName(peerHostSNI));
                    }
                    catch (RuntimeException e)
                    {
                        LOG.fine(clientID + ": Failed to add peer host as default SNI host_name: " + peerHostSNI);
                    }
                }
            }

            // NOTE: We follow SunJSSE behaviour and disable SNI if there are no server names to send
            if (null != sniServerNames && !sniServerNames.isEmpty())
            {
                Vector<ServerName> serverNames = new Vector<ServerName>(sniServerNames.size());
                for (BCSNIServerName sniServerName : sniServerNames)
                {
                    serverNames.add(new ServerName((short)sniServerName.getType(), sniServerName.getEncoded()));
                }
                return serverNames;
            }
        }
        return null;
    }

    @Override
    protected int[] getSupportedCipherSuites()
    {
        return manager.getContextData().getContext().getActiveCipherSuites(getCrypto(), sslParameters,
            getProtocolVersions());
    }

    @Override
    protected Vector<SignatureAndHashAlgorithm> getSupportedSignatureAlgorithms()
    {
        return jsseSecurityParameters.signatureSchemes.getLocalSignatureAndHashAlgorithms();
    }

    @Override
    protected Vector<SignatureAndHashAlgorithm> getSupportedSignatureAlgorithmsCert()
    {
        Vector<SignatureAndHashAlgorithm> result = jsseSecurityParameters.signatureSchemes
            .getLocalSignatureAndHashAlgorithmsCert();

        if (result == null && !provClientOmitSigAlgsCert)
        {
            result = jsseSecurityParameters.signatureSchemes.getLocalSignatureAndHashAlgorithms();
        }

        return result;
    }

    @Override
    protected ProtocolVersion[] getSupportedVersions()
    {
        return manager.getContextData().getContext().getActiveProtocolVersions(sslParameters);
    }

    @Override
    protected Vector<TrustedAuthority> getTrustedCAIndication()
    {
        if (provClientEnableTrustedCAKeys)
        {
            Vector<X500Name> certificateAuthorities = JsseUtils
                .getCertificateAuthorities(manager.getContextData().getX509TrustManager());

            if (null != certificateAuthorities)
            {
                Vector<TrustedAuthority> trustedCAKeys = new Vector<TrustedAuthority>(certificateAuthorities.size());
                for (X500Name certificateAuthority : certificateAuthorities)
                {
                    trustedCAKeys.add(new TrustedAuthority(IdentifierType.x509_name, certificateAuthority));
                }
                return trustedCAKeys;
            }
        }

        return null;
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
    public TlsDHGroupVerifier getDHGroupVerifier()
    {
        return new ProvDHGroupVerifier();
    }

    public TlsAuthentication getAuthentication() throws IOException
    {
        return new TlsAuthentication()
        {
            public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException
            {
                final ContextData contextData = manager.getContextData();
                final SecurityParameters securityParameters = context.getSecurityParametersHandshake();
                final ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();
                final boolean isTLSv13 = TlsUtils.isTLSv13(negotiatedVersion);

                // Setup the peer supported signature schemes  
                {
                    @SuppressWarnings("unchecked")
                    Vector<SignatureAndHashAlgorithm> serverSigAlgs = (Vector<SignatureAndHashAlgorithm>)
                        securityParameters.getServerSigAlgs();
                    @SuppressWarnings("unchecked")
                    Vector<SignatureAndHashAlgorithm> serverSigAlgsCert = (Vector<SignatureAndHashAlgorithm>)
                        securityParameters.getServerSigAlgsCert();

                    /*
                     * TODO[tls13] Legacy schemes (cert-only for TLS 1.3) complicate these conversions. Consider which
                     * (if any) of these should be constrained by locally enabled schemes (especially once
                     * jdk.tls.signatureSchemes support added).
                     */
                    List<SignatureSchemeInfo> peerSigSchemes = contextData.getSignatureSchemes(serverSigAlgs);
                    List<SignatureSchemeInfo> peerSigSchemesCert = null;
                    if (serverSigAlgsCert != serverSigAlgs)
                    {
                        peerSigSchemesCert = contextData.getSignatureSchemes(serverSigAlgsCert);
                    }

                    jsseSecurityParameters.signatureSchemes.notifyPeerData(peerSigSchemes, peerSigSchemesCert);

                    if (LOG.isLoggable(Level.FINEST))
                    {
                        {
                            String title = clientID + " peer signature_algorithms";
                            LOG.finest(JsseUtils.getSignatureAlgorithmsReport(title, peerSigSchemes));
                        }

                        if (peerSigSchemesCert != null)
                        {
                            String title = clientID + " peer signature_algorithms_cert";
                            LOG.finest(JsseUtils.getSignatureAlgorithmsReport(title, peerSigSchemesCert));
                        }
                    }
                }

                if (DummyX509KeyManager.INSTANCE == contextData.getX509KeyManager())
                {
                    return null;
                }

                @SuppressWarnings("unchecked")
                Principal[] issuers = JsseUtils.toX500Principals(certificateRequest.getCertificateAuthorities());

                byte[] certificateRequestContext = certificateRequest.getCertificateRequestContext();
                if (isTLSv13 != (null != certificateRequestContext))
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                short[] certificateTypes = certificateRequest.getCertificateTypes();
                if (isTLSv13 != (null == certificateTypes))
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                if (isTLSv13)
                {
                    return selectClientCredentials13(issuers, certificateRequestContext);
                }
                else if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(negotiatedVersion))
                {
                    return selectClientCredentials12(issuers, certificateTypes);
                }
                else
                {
                    return selectClientCredentialsLegacy(issuers, certificateTypes);
                }
            }

            public void notifyServerCertificate(TlsServerCertificate serverCertificate) throws IOException
            {
                if (null == serverCertificate || null == serverCertificate.getCertificate()
                    || serverCertificate.getCertificate().isEmpty())
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }

                X509Certificate[] chain = JsseUtils.getX509CertificateChain(getCrypto(),
                    serverCertificate.getCertificate());

                String authType = JsseUtils.getAuthTypeServer(
                    context.getSecurityParametersHandshake().getKeyExchangeAlgorithm());

                jsseSecurityParameters.statusResponses = JsseUtils.getStatusResponses(
                    serverCertificate.getCertificateStatus());

                manager.checkServerTrusted(chain, authType);
            }
        };
    }

    @Override
    public JcaTlsCrypto getCrypto()
    {
        return manager.getContextData().getCrypto();
    }

    @Override
    public int getMaxCertificateChainLength()
    {
        return JsseUtils.getMaxCertificateChainLength();
    }

    @Override
    public int getMaxHandshakeMessageSize()
    {
        return JsseUtils.getMaxHandshakeMessageSize();
    }

    @Override
    public TlsSession getSessionToResume()
    {
        if (provClientEnableSessionResumption)
        {
            ProvSSLSession availableSSLSession = sslParameters.getSessionToResume();
            if (null == availableSSLSession)
            {
                ProvSSLSessionContext sslSessionContext = manager.getContextData().getClientSessionContext();
                availableSSLSession = sslSessionContext.getSessionImpl(manager.getPeerHost(), manager.getPeerPort());
            }

            if (null != availableSSLSession)
            {
                TlsSession sessionToResume = availableSSLSession.getTlsSession();
                SessionParameters resumableSessionParameters = getResumableSessionParameters(availableSSLSession,
                    sessionToResume);
                if (null != resumableSessionParameters)
                {
                    this.sslSession = availableSSLSession;
                    if (!manager.getEnableSessionCreation())
                    {
                         // If session creation is disabled, only offer the session cipher suite.
                        this.cipherSuites = new int[]{ resumableSessionParameters.getCipherSuite() };
                    }
                    return sessionToResume;
                }
            }
        }

        JsseUtils.checkSessionCreationEnabled(manager);
        return null;
    }

    @Override
    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        super.notifyAlertRaised(alertLevel, alertDescription, message, cause);

        Level level = alertLevel == AlertLevel.warning                      ? Level.FINE
                    : alertDescription == AlertDescription.internal_error   ? Level.WARNING
                    :                                                         Level.INFO;

        if (LOG.isLoggable(level))
        {
            String msg = JsseUtils.getAlertRaisedLogMessage(clientID, alertLevel, alertDescription);
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
            String msg = JsseUtils.getAlertReceivedLogMessage(clientID, alertLevel, alertDescription);

            LOG.log(level, msg);
        }
    }

    @Override
    public void notifyConnectionClosed()
    {
        super.notifyConnectionClosed();

        if (LOG.isLoggable(Level.INFO))
        {
            LOG.info(clientID + " disconnected from " + JsseUtils.getPeerReport(manager));
        }
    }

    @Override
    public void notifyHandshakeBeginning() throws IOException
    {
        super.notifyHandshakeBeginning();

        if (LOG.isLoggable(Level.INFO))
        {
            LOG.info(clientID + " opening connection to " + JsseUtils.getPeerReport(manager));
        }

        ContextData contextData = manager.getContextData();
        ProtocolVersion[] activeProtocolVersions = getProtocolVersions();

        jsseSecurityParameters.namedGroups = contextData.getNamedGroupsClient(sslParameters, activeProtocolVersions);

        jsseSecurityParameters.signatureSchemes = contextData.getSignatureSchemesClient(sslParameters,
            activeProtocolVersions, jsseSecurityParameters.namedGroups);
    }

    @Override
    public synchronized void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        this.handshakeComplete = true;

        if (LOG.isLoggable(Level.INFO))
        {
            LOG.info(clientID + " established connection with " + JsseUtils.getPeerReport(manager));
        }

        TlsSession connectionTlsSession = context.getSession();

        if (null == sslSession || sslSession.getTlsSession() != connectionTlsSession)
        {
            ProvSSLSessionContext sslSessionContext = manager.getContextData().getClientSessionContext();
            String peerHost = manager.getPeerHost();
            int peerPort = manager.getPeerPort();
            JsseSessionParameters jsseSessionParameters = new JsseSessionParameters(
                sslParameters.getEndpointIdentificationAlgorithm(), null);
            // TODO[tls13] Resumption/PSK
            boolean addToCache = provClientEnableSessionResumption && !TlsUtils.isTLSv13(context);

            this.sslSession = sslSessionContext.reportSession(peerHost, peerPort, connectionTlsSession,
                jsseSessionParameters, addToCache);
        }

        manager.notifyHandshakeComplete(new ProvSSLConnection(this));
    }

    @Override
    public void notifySecureRenegotiation(boolean secureRenegotiation) throws IOException
    {
        if (!secureRenegotiation)
        {
            boolean allowLegacyHelloMessages = PropertyUtils.getBooleanSystemProperty(
                "sun.security.ssl.allowLegacyHelloMessages", true);

            if (!allowLegacyHelloMessages)
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
        }
    }

    @Override
    public void notifySelectedCipherSuite(int selectedCipherSuite)
    {
        String selectedCipherSuiteName = manager.getContextData().getContext()
            .validateNegotiatedCipherSuite(sslParameters, selectedCipherSuite);

        if (LOG.isLoggable(Level.FINE))
        {
            LOG.fine(clientID + " notified of selected cipher suite: " + selectedCipherSuiteName);
        }

        super.notifySelectedCipherSuite(selectedCipherSuite);
    }

    @Override
    public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException
    {
        String serverVersionName = manager.getContextData().getContext().validateNegotiatedProtocol(sslParameters,
            serverVersion);

        if (LOG.isLoggable(Level.FINE))
        {
            LOG.fine(clientID + " notified of selected protocol version: " + serverVersionName);
        }

        super.notifyServerVersion(serverVersion);
    }

    @Override
    public void notifySessionToResume(TlsSession session)
    {
        if (null == session)
        {
            JsseUtils.checkSessionCreationEnabled(manager);
        }

        super.notifySessionToResume(session);
    }

    @Override
    public void notifySessionID(byte[] sessionID)
    {
        final boolean isResumed = !TlsUtils.isNullOrEmpty(sessionID) && null != sslSession
            && Arrays.areEqual(sessionID, sslSession.getId());

        if (isResumed)
        {
            if (LOG.isLoggable(Level.FINE))
            {
                // -DM Hex.toHexString
                LOG.fine(clientID + ": Server resumed session: " + Hex.toHexString(sessionID));
            }
        }
        else
        {
            this.sslSession = null;

            if (LOG.isLoggable(Level.FINE))
            {
                if (TlsUtils.isNullOrEmpty(sessionID))
                {
                    LOG.fine(clientID + ": Server did not specify a session ID");
                }
                else
                {
                    // -DM Hex.toHexString
                    LOG.fine(clientID + ": Server specified new session: " + Hex.toHexString(sessionID));
                }
            }

            JsseUtils.checkSessionCreationEnabled(manager);
        }

        manager.notifyHandshakeSession(manager.getContextData().getClientSessionContext(),
            context.getSecurityParametersHandshake(), jsseSecurityParameters, sslSession);
    }

    @Override
    public void processServerExtensions(@SuppressWarnings("rawtypes") Hashtable serverExtensions) throws IOException
    {
        super.processServerExtensions(serverExtensions);

        SecurityParameters securityParameters = context.getSecurityParametersHandshake();

        if (null != securityParameters.getClientServerNames())
        {
            boolean sniAccepted = TlsExtensionsUtils.hasServerNameExtensionServer(serverExtensions);

            if (LOG.isLoggable(Level.FINER))
            {
                LOG.finer(clientID + ": Server accepted SNI?: " + sniAccepted);
            }
        }
    }

    @Override
    public boolean requiresCloseNotify()
    {
        return JsseUtils.requireCloseNotify();
    }

    @Override
    public boolean requiresExtendedMasterSecret()
    {
        return !JsseUtils.allowLegacyMasterSecret();
    }

    @Override
    public boolean shouldUseCompatibilityMode()
    {
        return JsseUtils.useCompatibilityMode();
    }

    @Override
    public boolean shouldUseExtendedMasterSecret()
    {
        return JsseUtils.useExtendedMasterSecret();
    }

    protected String[] getKeyTypesLegacy(short[] certificateTypes) throws IOException
    {
        String[] keyTypes = new String[certificateTypes.length];
        for (int i = 0; i < certificateTypes.length; ++i)
        {
            // TODO[jsse] Need to also take notice of certificateRequest.getSupportedSignatureAlgorithms(), if present
            keyTypes[i] = JsseUtils.getKeyTypeLegacyClient(certificateTypes[i]);
        }

        return keyTypes;
    }

    protected SessionParameters getResumableSessionParameters(ProvSSLSession provSSLSession, TlsSession tlsSession)
    {
        if (null == tlsSession || !tlsSession.isResumable())
        {
            return null;
        }

        // TODO[resumption] Avoid the copy somehow?
        SessionParameters sessionParameters = tlsSession.exportSessionParameters();

        {
            if (null == sessionParameters ||
                !Arrays.contains(getCipherSuites(), sessionParameters.getCipherSuite()))
            {
                return null;
            }

            ProtocolVersion sessionVersion = sessionParameters.getNegotiatedVersion();
            if (!ProtocolVersion.contains(getProtocolVersions(), sessionVersion))
            {
                return null;
            }

            // TODO[tls13] Resumption/PSK 
            if (TlsUtils.isTLSv13(sessionVersion))
            {
                return null;
            }
        }

        {
            String connectionEndpointID = sslParameters.getEndpointIdentificationAlgorithm();
            if (null != connectionEndpointID)
            {
                JsseSessionParameters jsseSessionParameters = provSSLSession.getJsseSessionParameters();
                String sessionEndpointID = jsseSessionParameters.getEndpointIDAlgorithm();
                if (!connectionEndpointID.equalsIgnoreCase(sessionEndpointID))
                {
                    if (LOG.isLoggable(Level.FINER))
                    {
                        LOG.finer(clientID + ": Session not resumable - endpoint ID algorithm mismatch; connection: "
                            + connectionEndpointID + ", session: " + sessionEndpointID);
                    }
                    return null;
                }
            }
        }

        return sessionParameters;
    }

    protected TlsCredentials selectClientCredentials12(Principal[] issuers, short[] certificateTypes)
        throws IOException
    {
        /*
         * RFC 5246 7.4.4 The end-entity certificate provided by the client MUST contain a key that
         * is compatible with certificate_types. If the key is a signature key, it MUST be usable
         * with some hash/signature algorithm pair in supported_signature_algorithms.
         */

        PerConnection signatureSchemes = jsseSecurityParameters.signatureSchemes;

        LinkedHashMap<String, SignatureSchemeInfo> keyTypeMap = new LinkedHashMap<String, SignatureSchemeInfo>();
        for (SignatureSchemeInfo signatureSchemeInfo : signatureSchemes.getPeerSigSchemes())
        {
            String keyType = signatureSchemeInfo.getKeyType();
            if (keyTypeMap.containsKey(keyType))
            {
                continue;
            }

            short signatureAlgorithm = signatureSchemeInfo.getSignatureAlgorithm();
            short certificateType = SignatureAlgorithm.getClientCertificateType(signatureAlgorithm);
            if (certificateType < 0 || !Arrays.contains(certificateTypes, certificateType))
            {
                continue;
            }

            if (!signatureSchemes.hasLocalSignatureScheme(signatureSchemeInfo))
            {
                continue;
            }

            keyTypeMap.put(keyType, signatureSchemeInfo);
        }

        if (keyTypeMap.isEmpty())
        {
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.fine(clientID + " (1.2) found no usable signature schemes");
            }
            return null;
        }

        String[] keyTypes = keyTypeMap.keySet().toArray(TlsUtils.EMPTY_STRINGS);
        BCX509Key x509Key = manager.chooseClientKey(keyTypes, issuers);

        if (null == x509Key)
        {
            handleKeyManagerMisses(keyTypeMap, null);
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.fine(clientID + " (1.2) did not select any credentials");
            }
            return null;
        }

        String selectedKeyType = x509Key.getKeyType();
        handleKeyManagerMisses(keyTypeMap, selectedKeyType);

        SignatureSchemeInfo selectedSignatureSchemeInfo = keyTypeMap.get(selectedKeyType);
        if (null == selectedSignatureSchemeInfo)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, "Key manager returned invalid key type");
        }

        if (LOG.isLoggable(Level.FINE))
        {
            LOG.fine(clientID + " (1.2) selected credentials for signature scheme '" + selectedSignatureSchemeInfo
                + "' (keyType '" + selectedKeyType + "'), with private key algorithm '"
                + JsseUtils.getPrivateKeyAlgorithm(x509Key.getPrivateKey()) + "'");
        }

        return JsseUtils.createCredentialedSigner(context, getCrypto(), x509Key,
            selectedSignatureSchemeInfo.getSignatureAndHashAlgorithm());
    }

    protected TlsCredentials selectClientCredentials13(Principal[] issuers, byte[] certificateRequestContext)
        throws IOException
    {
        PerConnection signatureSchemes = jsseSecurityParameters.signatureSchemes;

        LinkedHashMap<String, SignatureSchemeInfo> keyTypeMap = new LinkedHashMap<String, SignatureSchemeInfo>();
        for (SignatureSchemeInfo signatureSchemeInfo : signatureSchemes.getPeerSigSchemes())
        {
            if (!signatureSchemeInfo.isSupportedPost13() ||
                !signatureSchemes.hasLocalSignatureScheme(signatureSchemeInfo))
            {
                continue;
            }

            String keyType = signatureSchemeInfo.getKeyType13();
            if (keyTypeMap.containsKey(keyType))
            {
                continue;
            }

            keyTypeMap.put(keyType, signatureSchemeInfo);
        }

        if (keyTypeMap.isEmpty())
        {
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.fine(clientID + " (1.3) found no usable signature schemes");
            }
            return null;
        }

        String[] keyTypes = keyTypeMap.keySet().toArray(TlsUtils.EMPTY_STRINGS);
        BCX509Key x509Key = manager.chooseClientKey(keyTypes, issuers);

        if (null == x509Key)
        {
            handleKeyManagerMisses(keyTypeMap, null);
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.fine(clientID + " (1.3) did not select any credentials");
            }
            return null;
        }

        String selectedKeyType = x509Key.getKeyType();
        handleKeyManagerMisses(keyTypeMap, selectedKeyType);

        SignatureSchemeInfo selectedSignatureSchemeInfo = keyTypeMap.get(selectedKeyType);
        if (null == selectedSignatureSchemeInfo)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, "Key manager returned invalid key type");
        }

        if (LOG.isLoggable(Level.FINE))
        {
            LOG.fine(clientID + " (1.3) selected credentials for signature scheme '" + selectedSignatureSchemeInfo
                + "' (keyType '" + selectedKeyType + "'), with private key algorithm '"
                + JsseUtils.getPrivateKeyAlgorithm(x509Key.getPrivateKey()) + "'");
        }

        return JsseUtils.createCredentialedSigner13(context, getCrypto(), x509Key,
            selectedSignatureSchemeInfo.getSignatureAndHashAlgorithm(), certificateRequestContext);
    }

    protected TlsCredentials selectClientCredentialsLegacy(Principal[] issuers, short[] certificateTypes)
        throws IOException
    {
        String[] keyTypes = getKeyTypesLegacy(certificateTypes);
        if (keyTypes.length < 1)
        {
            return null;
        }

        BCX509Key x509Key = manager.chooseClientKey(keyTypes, issuers);
        if (null == x509Key)
        {
            return null;
        }

        return JsseUtils.createCredentialedSigner(context, getCrypto(), x509Key, null);
    }

    private void handleKeyManagerMisses(LinkedHashMap<String, SignatureSchemeInfo> keyTypeMap, String selectedKeyType)
    {
        for (Map.Entry<String, SignatureSchemeInfo> entry : keyTypeMap.entrySet())
        {
            String keyType = entry.getKey();
            if (keyType.equals(selectedKeyType))
            {
                break;
            }

            if (LOG.isLoggable(Level.FINER))
            {
                SignatureSchemeInfo signatureSchemeInfo = entry.getValue();

                LOG.finer(clientID + " found no credentials for signature scheme '" + signatureSchemeInfo
                    + "' (keyType '" + keyType + "')");
            }
        }
    }
}
