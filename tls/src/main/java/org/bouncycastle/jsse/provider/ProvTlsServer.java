package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jsse.BCSNIMatcher;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.jsse.BCX509Key;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.provider.SignatureSchemeInfo.PerConnection;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.CertificateStatus;
import org.bouncycastle.tls.ClientCertificateType;
import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.ServerName;
import org.bouncycastle.tls.SessionParameters;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsDHUtils;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.TrustedAuthority;
import org.bouncycastle.tls.crypto.DHGroup;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

class ProvTlsServer
    extends DefaultTlsServer
    implements ProvTlsPeer
{
    private static final Logger LOG = Logger.getLogger(ProvTlsServer.class.getName());

    private static final String PROPERTY_DEFAULT_DHE_PARAMETERS = "jdk.tls.server.defaultDHEParameters";

    // TODO[jsse] Integrate this into NamedGroupInfo
    private static final int provEphemeralDHKeySize = PropertyUtils.getIntegerSystemProperty("jdk.tls.ephemeralDHKeySize", 2048, 1024, 8192);

    /*
     * TODO[jsse] Does this selection override the restriction from 'jdk.tls.ephemeralDHKeySize'?
     * TODO[fips] Probably should be ignored in fips mode?
     */
    @SuppressWarnings("unused")
    private static final DHGroup[] provServerDefaultDHEParameters = getDefaultDHEParameters();

    private static final boolean provServerEnableCA = PropertyUtils
        .getBooleanSystemProperty("jdk.tls.server.enableCAExtension", true);

    private static final boolean provServerEnableSessionResumption = PropertyUtils
        .getBooleanSystemProperty("org.bouncycastle.jsse.server.enableSessionResumption", true);

    // TODO[jsse] Support status_request and status_request_v2 extensions
//    private static final boolean provServerEnableStatusRequest = PropertyUtils.getBooleanSystemProperty(
//        "jdk.tls.server.enableStatusRequestExtension", false);
    private static final boolean provServerEnableStatusRequest = false;

    private static final boolean provServerEnableTrustedCAKeys = PropertyUtils
        .getBooleanSystemProperty("org.bouncycastle.jsse.server.enableTrustedCAKeysExtension", false);

    private static final boolean provServerOmitSigAlgsCert = PropertyUtils
        .getBooleanSystemProperty("org.bouncycastle.jsse.server.omitSigAlgsCertExtension", true);

    private static DHGroup[] getDefaultDHEParameters()
    {
        String propertyValue = PropertyUtils.getStringSecurityProperty(PROPERTY_DEFAULT_DHE_PARAMETERS);
        if (null == propertyValue)
        {
            return null;
        }

        String input = JsseUtils.stripDoubleQuotes(JsseUtils.removeAllWhitespace(propertyValue));
        int limit = input.length();
        if (limit < 1)
        {
            return null;
        }

        ArrayList<DHGroup> result = new ArrayList<DHGroup>();
        int outerComma = -1;
        do
        {
            int openBrace = outerComma + 1;
            if (openBrace >= limit || '{' != input.charAt(openBrace))
            {
                break;
            }

            int modulus = openBrace + 1;

            int innerComma = input.indexOf(',', modulus);
            if (innerComma <= modulus)
            {
                break;
            }

            int generator = innerComma + 1;

            int closeBrace = input.indexOf('}', generator);
            if (closeBrace <= generator)
            {
                break;
            }

            try
            {
                BigInteger p = parseDHParameter(input, modulus, innerComma);
                BigInteger g = parseDHParameter(input, generator, closeBrace);

                DHGroup dhGroup = TlsDHUtils.getStandardGroupForDHParameters(p, g);
                if (null != dhGroup)
                {
                    result.add(dhGroup);
                }
                else if (!p.isProbablePrime(120))
                {
                    LOG.log(Level.WARNING, "Non-prime modulus ignored in security property ["
                        + PROPERTY_DEFAULT_DHE_PARAMETERS + "]: " + p.toString(16));
                }
                else
                {
                    result.add(new DHGroup(p, null, g, 0));
                }
            }
            catch (Exception e)
            {
                break;
            }

            outerComma = closeBrace + 1;
            if (outerComma >= limit)
            {
                return result.toArray(new DHGroup[result.size()]);
            }
        }
        while (',' == input.charAt(outerComma));

        LOG.log(Level.WARNING, "Invalid syntax for security property [" + PROPERTY_DEFAULT_DHE_PARAMETERS + "]");

        return null;
    }

    private static BigInteger parseDHParameter(String s, int beginIndex, int endIndex)
    {
        return new BigInteger(s.substring(beginIndex, endIndex), 16);
    }

    protected final String serverID;
    protected final ProvTlsManager manager;
    protected final ProvSSLParameters sslParameters;
    protected final JsseSecurityParameters jsseSecurityParameters = new JsseSecurityParameters();

    protected ProvSSLSession sslSession = null;
    protected BCSNIServerName matchedSNIServerName = null;
    protected Set<String> keyManagerMissCache = null;
    protected TlsCredentials credentials = null;
    protected boolean handshakeComplete = false;

    ProvTlsServer(ProvTlsManager manager, ProvSSLParameters sslParameters)
    {
        super(manager.getContextData().getCrypto());

        this.serverID = JsseUtils.getPeerID("server", manager);
        this.manager = manager;
        this.sslParameters = sslParameters.copyForConnection();
    }

    public String getID()
    {
        return serverID;
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
    protected boolean allowCertificateStatus()
    {
        return provServerEnableStatusRequest;
    }

    @Override
    protected boolean allowMultiCertStatus()
    {
        return provServerEnableStatusRequest;
    }

    @Override
    protected boolean allowTrustedCAIndication()
    {
        return null != jsseSecurityParameters.trustedIssuers;
    }

    @Override
    protected String getDetailMessageNoCipherSuite()
    {
        // CAUTION: Required for Common Criteria

        StringBuilder sb = new StringBuilder(serverID);
        
        int[] offered = offeredCipherSuites;
        if (TlsUtils.isNullOrEmpty(offered))
        {
            sb.append(" found no selectable cipher suite because none were offered.");
        }
        else
        {
            sb.append(" found no selectable cipher suite among the ");
            sb.append(offered.length);
            sb.append(" offered: ");

            ProvSSLContextSpi context = manager.getContextData().getContext();

            sb.append('[');
            JsseUtils.appendCipherSuiteDetail(sb, context, offered[0]);

            for (int i = 1; i < offered.length; ++i)
            {
                sb.append(", ");
                JsseUtils.appendCipherSuiteDetail(sb, context, offered[i]);
            }

            sb.append(']');
        }

        return sb.toString();
    }

    @Override
    protected int getMaximumNegotiableCurveBits()
    {
        return NamedGroupInfo.getMaximumBitsServerECDH(jsseSecurityParameters.namedGroups);
    }

    @Override
    protected int getMaximumNegotiableFiniteFieldBits()
    {
        int maxBits = NamedGroupInfo.getMaximumBitsServerFFDHE(jsseSecurityParameters.namedGroups);

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
        TlsCredentials cipherSuiteCredentials = null;

        int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(cipherSuite);
        if (!KeyExchangeAlgorithm.isAnonymous(keyExchangeAlgorithm))
        {
            cipherSuiteCredentials = selectCredentials(jsseSecurityParameters.trustedIssuers, keyExchangeAlgorithm);

            if (null == cipherSuiteCredentials)
            {
                String cipherSuiteName = ProvSSLContextSpi.getCipherSuiteName(cipherSuite);
                if (LOG.isLoggable(Level.FINER))
                {
                    LOG.finer(serverID + " found no credentials for cipher suite: " + cipherSuiteName);
                }
                return false;
            }
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

        return NamedGroupInfo.selectServerFFDHE(jsseSecurityParameters.namedGroups, minimumFiniteFieldBits);
    }

    @Override
    protected int selectDHDefault(int minimumFiniteFieldBits)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    protected int selectECDH(int minimumCurveBits)
    {
        return NamedGroupInfo.selectServerECDH(jsseSecurityParameters.namedGroups, minimumCurveBits);
    }

    @Override
    protected int selectECDHDefault(int minimumCurveBits)
    {
        throw new UnsupportedOperationException();
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

    public synchronized boolean isHandshakeComplete()
    {
        return handshakeComplete;
    }

    @Override
    public TlsCredentials getCredentials()
        throws IOException
    {
        if (credentials == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return credentials;
    }

    @Override
    public CertificateRequest getCertificateRequest() throws IOException
    {
        if (!isClientAuthEnabled())
        {
            return null;
        }

        final ContextData contextData = manager.getContextData();
        final ProtocolVersion negotiatedVersion = context.getServerVersion();

        Vector<SignatureAndHashAlgorithm> serverSigAlgs =
            jsseSecurityParameters.signatureSchemes.getLocalSignatureAndHashAlgorithms();

        Vector<X500Name> certificateAuthorities = null;
        if (provServerEnableCA)
        {
            certificateAuthorities = JsseUtils.getCertificateAuthorities(contextData.getX509TrustManager());
        }

        if (TlsUtils.isTLSv13(negotiatedVersion))
        {
            /*
             * TODO[tls13] RFC 8446 4.4.2.1. A server MAY request that a client present an OCSP response
             * with its certificate by sending an empty "status_request" extension in its
             * CertificateRequest message.
             */

            /*
             * RFC 8446 4.3.2. This field SHALL be zero length unless used for the post-handshake
             * authentication exchanges [..].
             */
            byte[] certificateRequestContext = TlsUtils.EMPTY_BYTES;

            Vector<SignatureAndHashAlgorithm> serverSigAlgsCert =
                jsseSecurityParameters.signatureSchemes.getLocalSignatureAndHashAlgorithmsCert();

            if (serverSigAlgsCert == null && !provServerOmitSigAlgsCert)
            {
                serverSigAlgsCert = jsseSecurityParameters.signatureSchemes.getLocalSignatureAndHashAlgorithms();
            }

            return new CertificateRequest(certificateRequestContext, serverSigAlgs, serverSigAlgsCert,
                certificateAuthorities);
        }

        // TODO[jsse] These should really be based on TlsCrypto support
        short[] certificateTypes = new short[]{ ClientCertificateType.ecdsa_sign,
            ClientCertificateType.rsa_sign, ClientCertificateType.dss_sign };

        return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
    }

    @Override
    public CertificateStatus getCertificateStatus() throws IOException
    {
        // TODO[jsse] Support status_request and status_request_v2 extensions
//        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
//        int statusRequestVersion = securityParameters.getStatusRequestVersion();
//
//        if (statusRequestVersion == 2)
//        {
//            int count = statusRequestV2.size();
//            for (int i = 0; i < count; ++i)
//            {
//                CertificateStatusRequestItemV2 item = (CertificateStatusRequestItemV2)statusRequestV2.get(i);
//                short statusType = item.getStatusType();
//                if (CertificateStatusType.ocsp_multi == statusType)
//                {
//                    int chainLength = credentials.getCertificate().getLength();
//                    Vector ocspResponseList = new Vector(chainLength);
//                    for (int j = 0; j < chainLength; ++j)
//                    {
//                        // TODO Actual OCSP response
//                        ocspResponseList.add(null);
//                    }
//
//                    return new CertificateStatus(CertificateStatusType.ocsp_multi, ocspResponseList);
//                }
//                else if (CertificateStatusType.ocsp == statusType)
//                {
//                    // TODO Actual OCSP response
//                    OCSPResponse ocspResponse;
//
//                    return new CertificateStatus(CertificateStatusType.ocsp, ocspResponse);
//                }
//            }
//        }
//        else if (statusRequestVersion == 1)
//        {
//            if (CertificateStatusType.ocsp == certificateStatusRequest.getStatusType())
//            {
//                OCSPStatusRequest ocspStatusRequest = certificateStatusRequest.getOCSPStatusRequest();
//
//                @SuppressWarnings("unchecked")
//                Vector<ResponderID> responderIDList = ocspStatusRequest.getResponderIDList();
//                Extensions requestExtensions = ocspStatusRequest.getRequestExtensions();
//
//                X509Certificate eeCert = JsseUtils.getEndEntity(getCrypto(), credentials.getCertificate());
//
//                // ...
//            }
//        }

        return null;
    }

    @Override
    public JcaTlsCrypto getCrypto()
    {
        return manager.getContextData().getCrypto();
    }

    @Override
    public int[] getSupportedGroups() throws IOException
    {
        // Setup the local supported groups
        {
            ContextData contextData = manager.getContextData();
            ProtocolVersion negotiatedVersion = context.getServerVersion();

            jsseSecurityParameters.namedGroups = contextData.getNamedGroupsServer(sslParameters, negotiatedVersion);
        }

        return NamedGroupInfo.getSupportedGroupsLocalServer(jsseSecurityParameters.namedGroups);
    }

    @Override
    public int getSelectedCipherSuite() throws IOException
    {
        final ContextData contextData = manager.getContextData();
        final SecurityParameters securityParameters = context.getSecurityParametersHandshake();

        // Set up the peer supported groups
        {
            int[] clientSupportedGroups = securityParameters.getClientSupportedGroups();

            jsseSecurityParameters.namedGroups.notifyPeerData(clientSupportedGroups);
        }

        // Setup the local supported signature schemes  
        {
            ProtocolVersion negotiatedVersion = context.getServerVersion();

            // TODO[jsse] May want this selection to depend on the peer's supported_groups
            jsseSecurityParameters.signatureSchemes = contextData.getSignatureSchemesServer(sslParameters,
                negotiatedVersion, jsseSecurityParameters.namedGroups);
        }

        // Setup the peer supported signature schemes  
        {
            @SuppressWarnings("unchecked")
            Vector<SignatureAndHashAlgorithm> clientSigAlgs = (Vector<SignatureAndHashAlgorithm>)
                securityParameters.getClientSigAlgs();
            @SuppressWarnings("unchecked")
            Vector<SignatureAndHashAlgorithm> clientSigAlgsCert = (Vector<SignatureAndHashAlgorithm>)
                securityParameters.getClientSigAlgsCert();

            /*
             * TODO[tls13] Legacy schemes (cert-only for TLS 1.3) complicate these conversions. Consider which
             * (if any) of these should be constrained by locally enabled schemes (especially once
             * jdk.tls.signatureSchemes support added).
             */
            List<SignatureSchemeInfo> peerSigSchemes = contextData.getSignatureSchemes(clientSigAlgs);
            List<SignatureSchemeInfo> peerSigSchemesCert = null;
            if (clientSigAlgsCert != clientSigAlgs)
            {
                peerSigSchemesCert = contextData.getSignatureSchemes(clientSigAlgsCert);
            }

            jsseSecurityParameters.signatureSchemes.notifyPeerData(peerSigSchemes, peerSigSchemesCert);

            if (LOG.isLoggable(Level.FINEST))
            {
                {
                    String title = serverID + " peer signature_algorithms";
                    LOG.finest(JsseUtils.getSignatureAlgorithmsReport(title, peerSigSchemes));
                }

                if (peerSigSchemesCert != null)
                {
                    String title = serverID + " peer signature_algorithms_cert";
                    LOG.finest(JsseUtils.getSignatureAlgorithmsReport(title, peerSigSchemesCert));
                }
            }
        }

        if (DummyX509KeyManager.INSTANCE == contextData.getX509KeyManager())
        {
            // We don't support anonymous cipher suites, so there has to be a (real) key manager
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        keyManagerMissCache = new HashSet<String>();

        int selectedCipherSuite = super.getSelectedCipherSuite();

        keyManagerMissCache = null;

        String selectedCipherSuiteName = contextData.getContext().validateNegotiatedCipherSuite(sslParameters,
            selectedCipherSuite);

        if (LOG.isLoggable(Level.FINE))
        {
            LOG.fine(serverID + " selected cipher suite: " + selectedCipherSuiteName);
        }

        return selectedCipherSuite;
    }

    @Override
    public Hashtable<Integer, byte[]> getServerExtensions() throws IOException
    {
        super.getServerExtensions();

        /*
         * RFC 6066 When resuming a session, the server MUST NOT include a server_name extension
         * in the server hello.
         */
        if (null != matchedSNIServerName)
        {
            // TODO[tls13] Resumption/PSK. SNI is always negotiated per-connection in TLS 1.3
            TlsExtensionsUtils.addServerNameExtensionServer(serverExtensions);
        }

        @SuppressWarnings("unchecked")
        Hashtable<Integer, byte[]> result = serverExtensions;

        return result;
    }

    @Override
    public TlsSession getSessionToResume(byte[] sessionID)
    {
        ProvSSLSessionContext sslSessionContext = manager.getContextData().getServerSessionContext();

        if (provServerEnableSessionResumption)
        {
            ProvSSLSession availableSSLSession = sslSessionContext.getSessionImpl(sessionID);

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

        JsseUtils.checkSessionCreationEnabled(manager);
        return null;
    }

    @Override
    public byte[] getNewSessionID()
    {
        // TODO[tls13] Resumption/PSK
        if (!provServerEnableSessionResumption || TlsUtils.isTLSv13(context))
        {
            return null;
        }

        return context.getNonceGenerator().generateNonce(32);
    }

    @Override
    public void notifySession(TlsSession session)
    {
        byte[] sessionID = session.getSessionID();

        boolean isResumed = (null != sslSession && sslSession.getTlsSession() == session);
        if (isResumed)
        {
            if (LOG.isLoggable(Level.FINE))
            {
                // -DM Hex.toHexString
                LOG.fine(serverID + " resumed session: " + Hex.toHexString(sessionID));
            }
        }
        else
        {
            this.sslSession = null;

            if (LOG.isLoggable(Level.FINE))
            {
                if (TlsUtils.isNullOrEmpty(sessionID))
                {
                    LOG.fine(serverID + " did not specify a session ID");
                }
                else
                {
                    // -DM Hex.toHexString
                    LOG.fine(serverID + " specified new session: " + Hex.toHexString(sessionID));
                }
            }

            JsseUtils.checkSessionCreationEnabled(manager);
        }

        manager.notifyHandshakeSession(manager.getContextData().getServerSessionContext(),
            context.getSecurityParametersHandshake(), jsseSecurityParameters, sslSession);
    }

    @Override
    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        Level level = alertLevel == AlertLevel.warning                      ? Level.FINE
                    : alertDescription == AlertDescription.internal_error   ? Level.WARNING
                    :                                                         Level.INFO;

        if (LOG.isLoggable(level))
        {
            String msg = JsseUtils.getAlertRaisedLogMessage(serverID, alertLevel, alertDescription);
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
            String msg = JsseUtils.getAlertReceivedLogMessage(serverID, alertLevel, alertDescription);

            LOG.log(level, msg);
        }
    }

    @Override
    public ProtocolVersion getServerVersion() throws IOException
    {
        ProtocolVersion serverVersion = super.getServerVersion();

        String serverVersionName = manager.getContextData().getContext().validateNegotiatedProtocol(sslParameters,
            serverVersion);

        if (LOG.isLoggable(Level.FINE))
        {
            LOG.fine(serverID + " selected protocol version: " + serverVersionName);
        }

        return serverVersion;
    }

    @Override
    public void notifyClientCertificate(Certificate clientCertificate) throws IOException
    {
        // NOTE: This method isn't called unless we returned non-null from getCertificateRequest() earlier
        if (!isClientAuthEnabled())
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

            /*
             * We never try to continue the handshake with an untrusted client certificate (although it could
             * be an option if we only "want" client-auth, rather than "need".
             * 
             * NOTE: The 'authType' parameter is a dummy value not used by trust managers.
             */
            manager.checkClientTrusted(chain, "TLS-client-auth");
        }
    }

    @Override
    public void notifyConnectionClosed()
    {
        super.notifyConnectionClosed();

        if (LOG.isLoggable(Level.INFO))
        {
            LOG.info(serverID + " disconnected from " + JsseUtils.getPeerReport(manager));
        }
    }

    @Override
    public void notifyHandshakeBeginning() throws IOException
    {
        super.notifyHandshakeBeginning();

        if (LOG.isLoggable(Level.INFO))
        {
            LOG.info(serverID + " accepting connection from " + JsseUtils.getPeerReport(manager));
        }
    }

    @Override
    public synchronized void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        this.handshakeComplete = true;

        if (LOG.isLoggable(Level.INFO))
        {
            LOG.info(serverID + " established connection with " + JsseUtils.getPeerReport(manager));
        }

        TlsSession connectionTlsSession = context.getSession();

        if (null == sslSession || sslSession.getTlsSession() != connectionTlsSession)
        {
            ProvSSLSessionContext sslSessionContext = manager.getContextData().getServerSessionContext();
            String peerHost = manager.getPeerHost();
            int peerPort = manager.getPeerPort();
            JsseSessionParameters jsseSessionParameters = new JsseSessionParameters(
                sslParameters.getEndpointIdentificationAlgorithm(), matchedSNIServerName);
            // TODO[tls13] Resumption/PSK
            boolean addToCache = provServerEnableSessionResumption && !TlsUtils.isTLSv13(context);

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
                if (LOG.isLoggable(Level.FINE))
                {
                    LOG.fine(serverID + " ignored SNI (no matchers specified)");
                }
            }
            else
            {
                this.matchedSNIServerName = JsseUtils.findMatchingSNIServerName(serverNameList, sniMatchers);
                if (null == matchedSNIServerName)
                {
                    throw new TlsFatalAlert(AlertDescription.unrecognized_name);
                }

                if (LOG.isLoggable(Level.FINE))
                {
                    LOG.fine(serverID + " accepted SNI: " + matchedSNIServerName);
                }
            }
        }

        if (TlsUtils.isTLSv13(context))
        {
            @SuppressWarnings("unchecked")
            Vector<X500Name> certificateAuthorities = TlsExtensionsUtils
                .getCertificateAuthoritiesExtension(clientExtensions);

            jsseSecurityParameters.trustedIssuers = JsseUtils.toX500Principals(certificateAuthorities);
        }
        else
        {
            if (provServerEnableTrustedCAKeys)
            {
                @SuppressWarnings("unchecked")
                Vector<TrustedAuthority> trustedCAKeys = this.trustedCAKeys;

                jsseSecurityParameters.trustedIssuers = JsseUtils.getTrustedIssuers(trustedCAKeys);
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
    public boolean shouldUseExtendedMasterSecret()
    {
        return JsseUtils.useExtendedMasterSecret();
    }

    protected boolean isClientAuthEnabled()
    {
        return sslParameters.getNeedClientAuth() || sslParameters.getWantClientAuth();
    }

    protected boolean isResumable(ProvSSLSession provSSLSession, TlsSession tlsSession)
    {
        if (null == tlsSession || !tlsSession.isResumable())
        {
            return false;
        }

        {
            SecurityParameters securityParameters = context.getSecurityParametersHandshake();

            ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();
            if (TlsUtils.isTLSv13(negotiatedVersion))
            {
                return false;
            }

            // TODO[resumption] Avoid the copy somehow?
            SessionParameters sessionParameters = tlsSession.exportSessionParameters();

            if (null == sessionParameters ||
                !negotiatedVersion.equals(sessionParameters.getNegotiatedVersion()) ||
                !Arrays.contains(getCipherSuites(), sessionParameters.getCipherSuite()) ||
                !Arrays.contains(offeredCipherSuites, sessionParameters.getCipherSuite()))
            {
                return false;
            }

            if (sslParameters.getNeedClientAuth() && sessionParameters.getPeerCertificate() == null)
            {
                return false;
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
                            LOG.finer(serverID + ": Session not resumable - endpoint ID algorithm mismatch; connection: "
                                + connectionEndpointID + ", session: " + sessionEndpointID);
                        }
                        return false;
                    }
                }
            }
        }

        {
            /*
             * TODO[tls13] RFC 8446 4.2.11. In TLS versions prior to TLS 1.3, the Server Name
             * Identification (SNI) value was intended to be associated with the session (Section 3
             * of [RFC6066]), with the server being required to enforce that the SNI value
             * associated with the session matches the one specified in the resumption handshake.
             * However, in reality the implementations were not consistent on which of two supplied
             * SNI values they would use, leading to the consistency requirement being de facto
             * enforced by the clients. In TLS 1.3, the SNI value is always explicitly specified in
             * the resumption handshake, and there is no need for the server to associate an SNI
             * value with the ticket. Clients, however, SHOULD store the SNI with the PSK to fulfill
             * the requirements of Section 4.6.1.
             */
            JsseSessionParameters jsseSessionParameters = provSSLSession.getJsseSessionParameters();

            BCSNIServerName connectionSNI = matchedSNIServerName;
            BCSNIServerName sessionSNI = jsseSessionParameters.getMatchedSNIServerName();

            if (!JsseUtils.equals(connectionSNI, sessionSNI))
            {
                if (LOG.isLoggable(Level.FINEST))
                {
                    LOG.finest(serverID + ": Session not resumable - SNI mismatch; connection: " + connectionSNI
                        + ", session: " + sessionSNI);
                }
                return false;
            }
        }

        return true;
    }

    protected TlsCredentials selectCredentials(Principal[] issuers, int keyExchangeAlgorithm) throws IOException
    {
        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_RSA:
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
        case KeyExchangeAlgorithm.RSA:
        {
            if (KeyExchangeAlgorithm.RSA == keyExchangeAlgorithm
                || !TlsUtils.isSignatureAlgorithmsExtensionAllowed(context.getServerVersion()))
            {
                return selectServerCredentialsLegacy(issuers, keyExchangeAlgorithm);
            }

            return selectServerCredentials12(issuers, keyExchangeAlgorithm);
        }

        case KeyExchangeAlgorithm.NULL:
        {
            byte[] certificateRequestContext = TlsUtils.EMPTY_BYTES;

            return selectServerCredentials13(issuers, certificateRequestContext);
        }

        default:
            return null;
        }
    }

    protected TlsCredentials selectServerCredentials12(Principal[] issuers, int keyExchangeAlgorithm) throws IOException
    {
        BCAlgorithmConstraints algorithmConstraints = sslParameters.getAlgorithmConstraints();

        final short legacySignatureAlgorithm = TlsUtils.getLegacySignatureAlgorithmServer(keyExchangeAlgorithm);

        PerConnection signatureSchemes = jsseSecurityParameters.signatureSchemes;

        LinkedHashMap<String, SignatureSchemeInfo> keyTypeMap = new LinkedHashMap<String, SignatureSchemeInfo>();
        for (SignatureSchemeInfo signatureSchemeInfo : signatureSchemes.getPeerSigSchemes())
        {
            if (!TlsUtils.isValidSignatureSchemeForServerKeyExchange(signatureSchemeInfo.getSignatureScheme(),
                keyExchangeAlgorithm))
            {
                continue;
            }

            final short signatureAlgorithm = signatureSchemeInfo.getSignatureAlgorithm();

            String keyType = (legacySignatureAlgorithm == signatureAlgorithm)
                ?   JsseUtils.getKeyTypeLegacyServer(keyExchangeAlgorithm)
                :   signatureSchemeInfo.getKeyType();

            if (keyManagerMissCache.contains(keyType))
            {
                continue;
            }
            if (keyTypeMap.containsKey(keyType))
            {
                continue;
            }

            // TODO[jsse] Somewhat redundant if we get all active signature schemes later (for CertificateRequest)
            if (!signatureSchemeInfo.isActive(algorithmConstraints, false, true, jsseSecurityParameters.namedGroups))
            {
                continue;
            }

            keyTypeMap.put(keyType, signatureSchemeInfo);
        }

        if (keyTypeMap.isEmpty())
        {
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.fine(serverID + " (1.2) has no key types to try for KeyExchangeAlgorithm " + keyExchangeAlgorithm);
            }
            return null;
        }

        String[] keyTypes = keyTypeMap.keySet().toArray(TlsUtils.EMPTY_STRINGS);
        BCX509Key x509Key = manager.chooseServerKey(keyTypes, issuers);

        if (null == x509Key)
        {
            handleKeyManagerMisses(keyTypeMap, null);
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.fine(serverID + " (1.2) did not select any credentials for KeyExchangeAlgorithm " + keyExchangeAlgorithm);
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
            LOG.fine(serverID + " (1.2) selected credentials for signature scheme '" + selectedSignatureSchemeInfo
                + "' (keyType '" + selectedKeyType + "'), with private key algorithm '"
                + JsseUtils.getPrivateKeyAlgorithm(x509Key.getPrivateKey()) + "'");
        }

        return JsseUtils.createCredentialedSigner(context, getCrypto(), x509Key,
            selectedSignatureSchemeInfo.getSignatureAndHashAlgorithm());
    }

    protected TlsCredentials selectServerCredentials13(Principal[] issuers, byte[] certificateRequestContext)
        throws IOException
    {
        BCAlgorithmConstraints algorithmConstraints = sslParameters.getAlgorithmConstraints();

        PerConnection signatureSchemes = jsseSecurityParameters.signatureSchemes;

        LinkedHashMap<String, SignatureSchemeInfo> keyTypeMap = new LinkedHashMap<String, SignatureSchemeInfo>();
        for (SignatureSchemeInfo signatureSchemeInfo : signatureSchemes.getPeerSigSchemes())
        {
            String keyType = signatureSchemeInfo.getKeyType13();
            if (keyManagerMissCache.contains(keyType))
            {
                continue;
            }
            if (keyTypeMap.containsKey(keyType))
            {
                continue;
            }

            // TODO[jsse] Somewhat redundant if we get all active signature schemes later (for CertificateRequest)
            if (!signatureSchemeInfo.isActive(algorithmConstraints, true, false, jsseSecurityParameters.namedGroups))
            {
                continue;
            }

            keyTypeMap.put(keyType, signatureSchemeInfo);
        }

        if (keyTypeMap.isEmpty())
        {
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.fine(serverID + " (1.3) found no usable signature schemes");
            }
            return null;
        }

        String[] keyTypes = keyTypeMap.keySet().toArray(TlsUtils.EMPTY_STRINGS);
        BCX509Key x509Key = manager.chooseServerKey(keyTypes, issuers);

        if (null == x509Key)
        {
            handleKeyManagerMisses(keyTypeMap, null);
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.fine(serverID + " (1.3) did not select any credentials");
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
            LOG.fine(serverID + " (1.3) selected credentials for signature scheme '" + selectedSignatureSchemeInfo
                + "' (keyType '" + selectedKeyType + "'), with private key algorithm '"
                + JsseUtils.getPrivateKeyAlgorithm(x509Key.getPrivateKey()) + "'");
        }

        return JsseUtils.createCredentialedSigner13(context, getCrypto(), x509Key,
            selectedSignatureSchemeInfo.getSignatureAndHashAlgorithm(), certificateRequestContext);
    }

    protected TlsCredentials selectServerCredentialsLegacy(Principal[] issuers, int keyExchangeAlgorithm)
        throws IOException
    {
        String keyType = JsseUtils.getKeyTypeLegacyServer(keyExchangeAlgorithm);
        if (keyManagerMissCache.contains(keyType))
        {
            return null;
        }

        BCX509Key x509Key = manager.chooseServerKey(new String[]{ keyType }, issuers);
        if (null == x509Key)
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

    private void handleKeyManagerMisses(LinkedHashMap<String, SignatureSchemeInfo> keyTypeMap, String selectedKeyType)
    {
        for (Map.Entry<String, SignatureSchemeInfo> entry : keyTypeMap.entrySet())
        {
            String keyType = entry.getKey();
            if (keyType.equals(selectedKeyType))
            {
                break;
            }

            keyManagerMissCache.add(keyType);

            if (LOG.isLoggable(Level.FINER))
            {
                SignatureSchemeInfo signatureSchemeInfo = entry.getValue();

                LOG.finer(serverID + " found no credentials for signature scheme '" + signatureSchemeInfo
                    + "' (keyType '" + keyType + "')");
            }
        }
    }
}
