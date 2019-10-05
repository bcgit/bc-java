package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.CertificateStatusRequest;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.ServerName;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsDHGroupVerifier;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaDefaultTlsCredentialedSigner;
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

    protected final ProvTlsManager manager;
    protected final ProvSSLParameters sslParameters;

    protected ProvSSLSession sslSession = null;
    protected boolean handshakeComplete = false;

    ProvTlsClient(ProvTlsManager manager, ProvSSLParameters sslParameters)
    {
        super(manager.getContextData().getCrypto());

        this.manager = manager;
        this.sslParameters = sslParameters.copyForConnection();
    }

    @Override
    protected Vector getProtocolNames()
    {
        return JsseUtils.getProtocolNames(sslParameters.getApplicationProtocols());
    }

    @Override
    protected CertificateStatusRequest getCertificateStatusRequest()
    {
        return null;
    }

    @Override
    protected Vector getSupportedGroups(Vector namedGroupRoles)
    {
        return SupportedGroups.getClientSupportedGroups(getCrypto(), manager.getContext().isFips(), namedGroupRoles);
    }

    @Override
    protected Vector getSNIServerNames()
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
                Vector serverNames = new Vector(sniServerNames.size());
                for (BCSNIServerName sniServerName : sniServerNames)
                {
                    serverNames.addElement(new ServerName((short)sniServerName.getType(), sniServerName.getEncoded()));
                }
                return serverNames;
            }
        }
        return null;
    }

    @Override
    protected int[] getSupportedCipherSuites()
    {
        return manager.getContext().getActiveCipherSuites(getCrypto(), sslParameters, getProtocolVersions());
    }

    @Override
    protected Vector getSupportedSignatureAlgorithms()
    {
        return JsseUtils.getSupportedSignatureAlgorithms(getCrypto());
    }

    @Override
    protected ProtocolVersion[] getSupportedVersions()
    {
        return manager.getContext().getActiveProtocolVersions(sslParameters);
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
                // TODO[jsse] What criteria determines whether we are willing to send client authentication?

                int selectedCipherSuite = context.getSecurityParametersHandshake().getCipherSuite();
                int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(selectedCipherSuite);
                switch (keyExchangeAlgorithm)
                {
                case KeyExchangeAlgorithm.DHE_DSS:
                case KeyExchangeAlgorithm.DHE_RSA:
                case KeyExchangeAlgorithm.ECDHE_ECDSA:
                case KeyExchangeAlgorithm.ECDHE_RSA:
                case KeyExchangeAlgorithm.RSA:
                    break;

                default:
                    /* Note: internal error here; selected a key exchange we don't implement! */
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                short[] certTypes = certificateRequest.getCertificateTypes();
                if (certTypes == null || certTypes.length == 0)
                {
                    // TODO[jsse] Or does this mean ANY type - or something else?
                    return null;
                }

                // TODO[RFC 8422] Rework this in light of ed25519/ed448 and handle the supported signature algorithms TODO
                String[] keyTypes = new String[certTypes.length];
                for (int i = 0; i < certTypes.length; ++i)
                {
                    // TODO[jsse] Need to also take notice of certificateRequest.getSupportedSignatureAlgorithms(), if present
                    keyTypes[i] = JsseUtils.getAuthTypeClient(certTypes[i]);
                }

                Principal[] issuers = null;
                Vector<X500Name> cas = (Vector<X500Name>)certificateRequest.getCertificateAuthorities();
                if (cas != null && cas.size() > 0)
                {
                	X500Name[] names = cas.toArray(new X500Name[cas.size()]);
                	Set<X500Principal> principals = JsseUtils.toX500Principals(names);
                	issuers = principals.toArray(new Principal[principals.size()]);
                }

                String alias = manager.chooseClientAlias(keyTypes, issuers);
                if (alias == null)
                {
                    return null;
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

                if (privateKey == null || certificate.isEmpty())
                {
                    // TODO[jsse] Log the probable misconfigured keystore
                    return null;
                }

                /*
                 * TODO[jsse] Before proceeding with EC credentials, should we check (TLS 1.2+) that
                 * the used curve was actually declared in the client's elliptic_curves/named_groups
                 * extension?
                 */

                switch (keyExchangeAlgorithm)
                {
                case KeyExchangeAlgorithm.DHE_DSS:
                case KeyExchangeAlgorithm.DHE_RSA:
                case KeyExchangeAlgorithm.ECDHE_ECDSA:
                case KeyExchangeAlgorithm.ECDHE_RSA:
                case KeyExchangeAlgorithm.RSA:
                {
                    short signatureAlgorithm = certificate.getCertificateAt(0).getLegacySignatureAlgorithm();
                    SignatureAndHashAlgorithm sigAlg = TlsUtils.chooseSignatureAndHashAlgorithm(context,
                        context.getSecurityParametersHandshake().getClientSigAlgs(), signatureAlgorithm);

                    // TODO[jsse] Need to have TlsCrypto construct the credentials from the certs/key
                    return new JcaDefaultTlsCredentialedSigner(new TlsCryptoParameters(context), (JcaTlsCrypto)crypto,
                        privateKey, certificate, sigAlg);
                }

                default:
                    /* Note: internal error here; selected a key exchange we don't implement! */
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }
            }

            public void notifyServerCertificate(TlsServerCertificate serverCertificate) throws IOException
            {
                if (null == serverCertificate || null == serverCertificate.getCertificate()
                    || serverCertificate.getCertificate().isEmpty())
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }

                X509Certificate[] chain = JsseUtils.getX509CertificateChain(getCrypto(), serverCertificate.getCertificate());
                int selectedCipherSuite = context.getSecurityParametersHandshake().getCipherSuite();
                String authType = JsseUtils.getAuthTypeServer(TlsUtils.getKeyExchangeAlgorithm(selectedCipherSuite));

                manager.checkServerTrusted(chain, authType);
            }
        };
    }

    @Override
    public TlsSession getSessionToResume()
    {
        ProvSSLSessionContext sslSessionContext = manager.getContextData().getClientSessionContext();
        ProvSSLSession availableSSLSession = sslSessionContext.getSessionImpl(manager.getPeerHost(), manager.getPeerPort());

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
        manager.getContext().validateNegotiatedCipherSuite(sslParameters, selectedCipherSuite);

        String selectedCipherSuiteName = ProvSSLContextSpi.getCipherSuiteName(selectedCipherSuite);

        LOG.fine("Client notified of selected cipher suite: " + selectedCipherSuiteName);

        super.notifySelectedCipherSuite(selectedCipherSuite);
    }

    @Override
    public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException
    {
        manager.getContext().validateNegotiatedProtocol(sslParameters, serverVersion);

        String serverVersionName = ProvSSLContextSpi.getProtocolVersionName(serverVersion);

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
                handshakeSession = new ProvSSLSessionHandshake(sslSessionContext, peerHost, peerPort, securityParameters);
            }
            else
            {
                handshakeSession = new ProvSSLSessionResumed(sslSessionContext, peerHost, peerPort, securityParameters,
                    sslSession.getTlsSession(), sslSession.getJsseSessionParameters());
            }

            manager.notifyHandshakeSession(handshakeSession);
        }
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
