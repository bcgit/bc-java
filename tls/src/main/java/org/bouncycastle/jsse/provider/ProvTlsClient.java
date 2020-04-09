package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
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
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsDHGroupVerifier;
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
    protected Vector<ProtocolName> getProtocolNames()
    {
        return JsseUtils.getProtocolNames(sslParameters.getApplicationProtocols());
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
    protected Vector<Integer> getSupportedGroups(@SuppressWarnings("rawtypes") Vector namedGroupRolesRaw)
    {
        @SuppressWarnings("unchecked")
        Vector<Integer> namedGroupRoles = namedGroupRolesRaw;

        return SupportedGroups.getClientSupportedGroups(getCrypto(), manager.getContextData().getContext().isFips(),
            namedGroupRoles);
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

        List<SignatureSchemeInfo> signatureSchemes = contextData.getActiveSignatureSchemes(sslParameters,
            getProtocolVersions());

        // TODO[tls13] Legacy schemes (cert-only for TLS 1.3) complicate this 
        jsseSecurityParameters.localSigSchemes = signatureSchemes;
        jsseSecurityParameters.localSigSchemesCert = signatureSchemes;

        return contextData.getSignatureAndHashAlgorithms(signatureSchemes);
    }

    @Override
    protected Vector<SignatureAndHashAlgorithm> getSupportedSignatureAlgorithmsCert()
    {
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

                // Setup the peer supported signature schemes  
                {
                    @SuppressWarnings("unchecked")
                    Vector<SignatureAndHashAlgorithm> serverSigAlgs = (Vector<SignatureAndHashAlgorithm>)
                        securityParameters.getServerSigAlgs();
                    @SuppressWarnings("unchecked")
                    Vector<SignatureAndHashAlgorithm> serverSigAlgsCert = (Vector<SignatureAndHashAlgorithm>)
                        securityParameters.getServerSigAlgsCert();

                    // TODO[tls13] Legacy schemes (cert-only for TLS 1.3) complicate these conversions 
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

                // TODO[tls13] Should be null from TLS 1.3
                short[] certificateTypes = certificateRequest.getCertificateTypes();

                if (!TlsUtils.isSignatureAlgorithmsExtensionAllowed(securityParameters.getNegotiatedVersion()))
                {
                    return chooseClientCredentialsLegacy(issuers, certificateTypes);
                }

                return chooseClientCredentials(issuers, certificateTypes);
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
        ProvSSLSession availableSSLSession = sslParameters.getSessionToResume();
        if (null == availableSSLSession)
        {
            ProvSSLSessionContext sslSessionContext = manager.getContextData().getClientSessionContext();
            availableSSLSession = sslSessionContext.getSessionImpl(manager.getPeerHost(), manager.getPeerPort());
        }

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
            boolean allowLegacyHelloMessages = PropertyUtils.getBooleanSystemProperty(
                "sun.security.ssl.allowLegacyHelloMessages", true);
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

        {
            ProvSSLSessionContext sslSessionContext = manager.getContextData().getClientSessionContext();
            String peerHost = manager.getPeerHost();
            int peerPort = manager.getPeerPort();
            SecurityParameters securityParameters = context.getSecurityParametersHandshake();

            ProvSSLSessionHandshake handshakeSession;
            if (!isResumed)
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

    protected TlsCredentials chooseClientCredentials(Principal[] issuers, short[] certificateTypes)
        throws IOException
    {
        /*
         * RFC 5246 7.4.4 The end-entity certificate provided by the client MUST contain a key that
         * is compatible with certificate_types. If the key is a signature key, it MUST be usable
         * with some hash/signature algorithm pair in supported_signature_algorithms.
         */

        BCAlgorithmConstraints algorithmConstraints = sslParameters.getAlgorithmConstraints();
        Set<String> keyManagerMissCache = new HashSet<String>();

        for (SignatureSchemeInfo signatureSchemeInfo : jsseSecurityParameters.peerSigSchemes)
        {
            String keyType = JsseUtils.getKeyType(signatureSchemeInfo);
            if (keyManagerMissCache.contains(keyType))
            {
                continue;
            }

            if (null != certificateTypes)
            {
                short signatureAlgorithm = signatureSchemeInfo.getSignatureAlgorithm();
                short certificateType = SignatureAlgorithm.getClientCertificateType(signatureAlgorithm);
                if (certificateType < 0 || !Arrays.contains(certificateTypes, certificateType))
                {
                    continue;
                }
            }

            if (!signatureSchemeInfo.isActive(algorithmConstraints))
            {
                continue;
            }

            ProvX509Key x509Key = manager.chooseClientKey(new String[]{ keyType }, issuers);
            if (null == x509Key)
            {
                keyManagerMissCache.add(keyType);
                continue;
            }

            return JsseUtils.createCredentialedSigner(context, getCrypto(), x509Key,
                signatureSchemeInfo.getSignatureAndHashAlgorithm());
        }

        return null;
    }

    protected TlsCredentials chooseClientCredentialsLegacy(Principal[] issuers, short[] certificateTypes)
        throws IOException
    {
        String[] keyTypes = getKeyTypesLegacy(certificateTypes);

        ProvX509Key x509Key = manager.chooseClientKey(keyTypes, issuers);
        if (null == x509Key)
        {
            return null;
        }

        return JsseUtils.createCredentialedSigner(context, getCrypto(), x509Key, null);
    }

    protected String[] getKeyTypesLegacy(short[] certificateTypes) throws IOException
    {
        if (null == certificateTypes || certificateTypes.length == 0)
        {
            // TODO[jsse] Or does this mean ANY type - or something else?
            return null;
        }

        String[] keyTypes = new String[certificateTypes.length];
        for (int i = 0; i < certificateTypes.length; ++i)
        {
            // TODO[jsse] Need to also take notice of certificateRequest.getSupportedSignatureAlgorithms(), if present
            keyTypes[i] = JsseUtils.getKeyTypeLegacyClient(certificateTypes[i]);
        }

        return keyTypes;
    }

    protected boolean isResumable(ProvSSLSession availableSSLSession)
    {
        // TODO[jsse] We could check EMS here, although the protocol classes reject non-EMS sessions anyway

        JsseSessionParameters jsseSessionParameters = availableSSLSession.getJsseSessionParameters();

        String endpointIDAlgorithm = sslParameters.getEndpointIdentificationAlgorithm();
        if (null != endpointIDAlgorithm)
        {
            String identificationProtocol = jsseSessionParameters.getIdentificationProtocol();
            if (!endpointIDAlgorithm.equalsIgnoreCase(identificationProtocol))
            {
                LOG.finest("Session not resumed - endpoint ID algorithm mismatch; requested: " + endpointIDAlgorithm
                    + ", session: " + identificationProtocol);
                return false;
            }
        }

        return true;
    }
}
