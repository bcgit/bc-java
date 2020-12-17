package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.jsse.BCX509Key;
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

    private static final boolean provEnableSNIExtension = PropertyUtils.getBooleanSystemProperty("jsse.enableSNIExtension", true);
    private static final boolean provClientEnableStatusRequest = PropertyUtils.getBooleanSystemProperty(
        "jdk.tls.client.enableStatusRequestExtension", true);

    private static final boolean provClientEnableSessionResumption = PropertyUtils
        .getBooleanSystemProperty("org.bouncycastle.jsse.client.enableSessionResumption", true);

    private static final boolean provClientEnableTrustedCAKeys = PropertyUtils
        .getBooleanSystemProperty("org.bouncycastle.jsse.client.enableTrustedCAKeysExtension", false);

    protected final ProvTlsManager manager;
    protected final ProvSSLParameters sslParameters;
    protected final JsseSecurityParameters jsseSecurityParameters = new JsseSecurityParameters();

    protected ProvSSLSession sslSession = null;
    protected boolean handshakeComplete = false;

    ProvTlsClient(ProvTlsManager manager, ProvSSLParameters sslParameters)
    {
        super(manager.getContextData().getCrypto());

        this.manager = manager;
        this.sslParameters = sslParameters.copyForConnection();
    }

    @Override
    protected Vector<X500Name> getCertificateAuthorities()
    {
        /*
         * TODO[tls13] It appears SunJSSE will add a system property for this (default disabled?),
         * perhaps "jdk.tls[.client/server].enableCAExtension" or similar.
         * 
         * TODO[tls13] Avoid duplication b/w this method and getTrustedCAIndication.
         */
//        return JsseUtils.getCertificateAuthorities(manager.getContextData().getX509TrustManager());
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
                        LOG.fine("Failed to add peer host as default SNI host_name: " + peerHostSNI);
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
        ContextData contextData = manager.getContextData();
        ProtocolVersion[] activeProtocolVersions = getProtocolVersions();

        List<SignatureSchemeInfo> signatureSchemes = contextData.getActiveCertsSignatureSchemes(false, sslParameters,
            activeProtocolVersions, jsseSecurityParameters.namedGroups);

        jsseSecurityParameters.localSigSchemes = signatureSchemes;
        jsseSecurityParameters.localSigSchemesCert = signatureSchemes;

        return SignatureSchemeInfo.getSignatureAndHashAlgorithms(jsseSecurityParameters.localSigSchemes);
    }

    @Override
    protected Vector<SignatureAndHashAlgorithm> getSupportedSignatureAlgorithmsCert()
    {
//        if (jsseSecurityParameters.localSigSchemes != jsseSecurityParameters.localSigSchemesCert)
//        {
//            return SignatureSchemeInfo.getSignatureAndHashAlgorithms(jsseSecurityParameters.localSigSchemesCert);
//        }

        return null;
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
                    jsseSecurityParameters.peerSigSchemes = contextData.getSignatureSchemes(serverSigAlgs);
                    jsseSecurityParameters.peerSigSchemesCert = (serverSigAlgs == serverSigAlgsCert)
                        ?   jsseSecurityParameters.peerSigSchemes
                        :   contextData.getSignatureSchemes(serverSigAlgsCert);
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
                if (isResumable(availableSSLSession, sessionToResume))
                {
                    this.sslSession = availableSSLSession;
                    return sessionToResume;
                }
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
        super.notifyAlertRaised(alertLevel, alertDescription, message, cause);

        Level level = alertLevel == AlertLevel.warning                      ? Level.FINE
                    : alertDescription == AlertDescription.internal_error   ? Level.WARNING
                    :                                                         Level.INFO;

        if (LOG.isLoggable(level))
        {
            String msg = JsseUtils.getAlertLogMessage("Client raised", alertLevel, alertDescription);
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
            String msg = JsseUtils.getAlertLogMessage("Client received", alertLevel, alertDescription);

            LOG.log(level, msg);
        }
    }

    @Override
    public void notifyHandshakeBeginning() throws IOException
    {
        super.notifyHandshakeBeginning();

        ContextData contextData = manager.getContextData();
        ProtocolVersion[] activeProtocolVersions = getProtocolVersions();

        jsseSecurityParameters.namedGroups = contextData.getNamedGroups(sslParameters, activeProtocolVersions);
    }

    @Override
    public synchronized void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        this.handshakeComplete = true;

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

        manager.notifyHandshakeComplete(new ProvSSLConnection(context, sslSession));
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

        LOG.fine("Client notified of selected cipher suite: " + selectedCipherSuiteName);

        super.notifySelectedCipherSuite(selectedCipherSuite);
    }

    @Override
    public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException
    {
        String serverVersionName = manager.getContextData().getContext().validateNegotiatedProtocol(sslParameters,
            serverVersion);

        LOG.fine("Client notified of selected protocol version: " + serverVersionName);

        super.notifyServerVersion(serverVersion);
    }

    @Override
    public void notifySessionID(byte[] sessionID)
    {
        final boolean isResumed = (null != sessionID && sessionID.length > 0 && null != sslSession
            && Arrays.areEqual(sessionID, sslSession.getId()));

        if (isResumed)
        {
            LOG.fine("Server resumed session: " + Hex.toHexString(sessionID));
        }
        else
        {
            this.sslSession = null;

            if (sessionID == null || sessionID.length < 1)
            {
                LOG.fine("Server did not specify a session ID");
            }
            else
            {
                LOG.fine("Server specified new session: " + Hex.toHexString(sessionID));
            }

            if (!manager.getEnableSessionCreation())
            {
                throw new IllegalStateException("Server did not resume session and session creation is disabled");
            }
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

            LOG.finer("Server accepted SNI?: " + sniAccepted);
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

    protected boolean isResumable(ProvSSLSession provSSLSession, TlsSession tlsSession)
    {
        if (null == tlsSession || !tlsSession.isResumable())
        {
            return false;
        }

        {
            // TODO[resumption] Avoid the copy somehow?
            SessionParameters sessionParameters = tlsSession.exportSessionParameters();

            // TODO[resumption] We could check EMS here, although the protocol classes reject non-EMS sessions anyway
            if (null == sessionParameters ||
                !ProtocolVersion.contains(getProtocolVersions(), sessionParameters.getNegotiatedVersion()) ||
                !Arrays.contains(getCipherSuites(), sessionParameters.getCipherSuite()))
            {
                return false;
            }

            // TODO[tls13] Resumption/PSK 
            if (TlsUtils.isTLSv13(sessionParameters.getNegotiatedVersion()))
            {
                return false;
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
                    LOG.finest("Session not resumable - endpoint ID algorithm mismatch; connection: "
                        + connectionEndpointID + ", session: " + sessionEndpointID);
                    return false;
                }
            }
        }

        return true;
    }

    protected TlsCredentials selectClientCredentials12(Principal[] issuers, short[] certificateTypes)
        throws IOException
    {
        /*
         * RFC 5246 7.4.4 The end-entity certificate provided by the client MUST contain a key that
         * is compatible with certificate_types. If the key is a signature key, it MUST be usable
         * with some hash/signature algorithm pair in supported_signature_algorithms.
         */

        Set<String> keyManagerMissCache = new HashSet<String>();

        for (SignatureSchemeInfo signatureSchemeInfo : jsseSecurityParameters.peerSigSchemes)
        {
            String keyType = JsseUtils.getKeyType(signatureSchemeInfo);
            if (keyManagerMissCache.contains(keyType))
            {
                continue;
            }

            short signatureAlgorithm = signatureSchemeInfo.getSignatureAlgorithm();
            short certificateType = SignatureAlgorithm.getClientCertificateType(signatureAlgorithm);
            if (certificateType < 0 || !Arrays.contains(certificateTypes, certificateType))
            {
                continue;
            }

            if (!jsseSecurityParameters.localSigSchemes.contains(signatureSchemeInfo))
            {
                continue;
            }

            BCX509Key x509Key = manager.chooseClientKey(new String[]{ keyType }, issuers);
            if (null == x509Key)
            {
                if (LOG.isLoggable(Level.FINER))
                {
                    LOG.finer("Client (1.2) found no credentials for signature scheme '" + signatureSchemeInfo
                        + "' (keyType '" + keyType + "')");
                }

                keyManagerMissCache.add(keyType);
                continue;
            }

            if (LOG.isLoggable(Level.FINE))
            {
                LOG.fine("Client (1.2) selected credentials for signature scheme '" + signatureSchemeInfo
                    + "' (keyType '" + keyType + "'), with private key algorithm '"
                    + JsseUtils.getPrivateKeyAlgorithm(x509Key.getPrivateKey()) + "'");
            }

            return JsseUtils.createCredentialedSigner(context, getCrypto(), x509Key,
                signatureSchemeInfo.getSignatureAndHashAlgorithm());
        }

        LOG.fine("Client (1.2) did not select any credentials");

        return null;
    }

    protected TlsCredentials selectClientCredentials13(Principal[] issuers, byte[] certificateRequestContext)
        throws IOException
    {
        Set<String> keyManagerMissCache = new HashSet<String>();

        for (SignatureSchemeInfo signatureSchemeInfo : jsseSecurityParameters.peerSigSchemes)
        {
            if (!signatureSchemeInfo.isSupported13() ||
                !jsseSecurityParameters.localSigSchemes.contains(signatureSchemeInfo))
            {
                continue;
            }

            String keyType = JsseUtils.getKeyType(signatureSchemeInfo);
            if (keyManagerMissCache.contains(keyType))
            {
                continue;
            }

            BCX509Key x509Key = manager.chooseClientKey(new String[]{ keyType }, issuers);
            if (null == x509Key)
            {
                if (LOG.isLoggable(Level.FINER))
                {
                    LOG.finer("Client (1.3) found no credentials for signature scheme '" + signatureSchemeInfo
                        + "' (keyType '" + keyType + "')");
                }

                keyManagerMissCache.add(keyType);
                continue;
            }

            if (LOG.isLoggable(Level.FINE))
            {
                LOG.fine("Client (1.3) selected credentials for signature scheme '" + signatureSchemeInfo
                    + "' (keyType '" + keyType + "'), with private key algorithm '"
                    + JsseUtils.getPrivateKeyAlgorithm(x509Key.getPrivateKey()) + "'");
            }

            return JsseUtils.createCredentialedSigner13(context, getCrypto(), x509Key,
                signatureSchemeInfo.getSignatureAndHashAlgorithm(), certificateRequestContext);
        }

        LOG.fine("Client (1.3) did not select any credentials");

        return null;
    }

    protected TlsCredentials selectClientCredentialsLegacy(Principal[] issuers, short[] certificateTypes)
        throws IOException
    {
        String[] keyTypes = getKeyTypesLegacy(certificateTypes);

        BCX509Key x509Key = manager.chooseClientKey(keyTypes, issuers);
        if (null == x509Key)
        {
            return null;
        }

        return JsseUtils.createCredentialedSigner(context, getCrypto(), x509Key, null);
    }
}
