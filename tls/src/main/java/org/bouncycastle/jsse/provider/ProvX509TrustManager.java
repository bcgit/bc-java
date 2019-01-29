package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Provider;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCStandardConstants;
import org.bouncycastle.jsse.BCX509ExtendedTrustManager;

class ProvX509TrustManager
    extends BCX509ExtendedTrustManager
{
    private static final Logger LOG = Logger.getLogger(ProvX509TrustManager.class.getName());

    private static Set<X509Certificate> getTrustedCerts(Set<TrustAnchor> trustAnchors)
    {
        Set<X509Certificate> result = new HashSet<X509Certificate>(trustAnchors.size());
        for (TrustAnchor trustAnchor : trustAnchors)
        {
            if (trustAnchor != null)
            {
                X509Certificate trustedCert = trustAnchor.getTrustedCert();
                if (trustedCert != null)
                {
                    result.add(trustedCert);
                }
            }
        }
        return result;
    }

    private final Provider pkixProvider;
    private final Set<X509Certificate> trustedCerts;
    private final PKIXParameters baseParameters;
    private final X509TrustManager exportX509TrustManager;

    ProvX509TrustManager(Provider pkixProvider, Set<TrustAnchor> trustAnchors)
        throws InvalidAlgorithmParameterException
    {
        this.pkixProvider = pkixProvider;
        this.trustedCerts = getTrustedCerts(trustAnchors);
        this.baseParameters = new PKIXBuilderParameters(trustAnchors, new X509CertSelector());
        this.baseParameters.setRevocationEnabled(false);
        this.exportX509TrustManager = X509TrustManagerUtil.exportX509TrustManager(this);
    }

    ProvX509TrustManager(Provider pkixProvider, PKIXParameters baseParameters)
        throws InvalidAlgorithmParameterException
    {
        this.pkixProvider = pkixProvider;
        this.trustedCerts = getTrustedCerts(baseParameters.getTrustAnchors());
        if (baseParameters instanceof PKIXBuilderParameters)
        {
            this.baseParameters = baseParameters;
        }
        else
        {
            this.baseParameters = new PKIXBuilderParameters(baseParameters.getTrustAnchors(), baseParameters.getTargetCertConstraints());
            this.baseParameters.setCertStores(baseParameters.getCertStores());
            this.baseParameters.setRevocationEnabled(baseParameters.isRevocationEnabled());
            this.baseParameters.setCertPathCheckers(baseParameters.getCertPathCheckers());
            this.baseParameters.setDate(baseParameters.getDate());
            this.baseParameters.setAnyPolicyInhibited(baseParameters.isAnyPolicyInhibited());
            this.baseParameters.setPolicyMappingInhibited(baseParameters.isPolicyMappingInhibited());
            this.baseParameters.setExplicitPolicyRequired(baseParameters.isExplicitPolicyRequired());
        }
        this.exportX509TrustManager = X509TrustManagerUtil.exportX509TrustManager(this);
    }

    X509TrustManager getExportX509TrustManager()
    {
        return exportX509TrustManager;
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType)
        throws CertificateException
    {
        checkTrusted(chain, authType, (Socket)null, false);
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
        throws CertificateException
    {
        checkTrusted(chain, authType, socket, false);
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
        throws CertificateException
    {
        checkTrusted(chain, authType, engine, false);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType)
        throws CertificateException
    {
        checkTrusted(chain, authType, (Socket)null, true);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
        throws CertificateException
    {
        checkTrusted(chain, authType, socket, true);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
        throws CertificateException
    {
        checkTrusted(chain, authType, engine, true);
    }

    public X509Certificate[] getAcceptedIssuers()
    {
        return trustedCerts.toArray(new X509Certificate[trustedCerts.size()]);
    }

    private void checkTrusted(X509Certificate[] chain, String authType, Socket socket, boolean isServer)
        throws CertificateException
    {
        validatePath(chain, authType, isServer);

        checkExtendedTrust(chain, authType, socket, isServer);
    }

    private void checkTrusted(X509Certificate[] chain, String authType, SSLEngine engine, boolean isServer)
        throws CertificateException
    {
        validatePath(chain, authType, isServer);

        checkExtendedTrust(chain, authType, engine, isServer);
    }

    private void validatePath(X509Certificate[] chain, String authType, boolean isServer)
        throws CertificateException
    {
        if (null == chain || chain.length < 1)
        {
            throw new IllegalArgumentException("'chain' must be a chain of at least one certificate");
        }
        if (null == authType || authType.length() < 1)
        {
            throw new IllegalArgumentException("'authType' must be a non-null, non-empty string");
        }

        // TODO[jsse] Further 'authType'-related checks (at least for server certificates)
//        String validationAuthType = isServer ? authType : null;

        X509Certificate eeCert = chain[0];
        if (trustedCerts.contains(eeCert))
        {
            return;
        }

        try
        {
            /*
             * TODO[jsse] When 'isServer', make use of any status responses (OCSP) via
             * BCExtendedSSLSession.getStatusResponses()
             */

            CertStore certStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(Arrays.asList(chain)), pkixProvider);

            CertPathBuilder pathBuilder = CertPathBuilder.getInstance("PKIX", pkixProvider);

            X509CertSelector constraints = (X509CertSelector)baseParameters.getTargetCertConstraints().clone();

            constraints.setCertificate(eeCert);

            PKIXBuilderParameters param = (PKIXBuilderParameters)baseParameters.clone();

            param.addCertStore(certStore);
            param.setTargetCertConstraints(constraints);

            @SuppressWarnings("unused")
            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)pathBuilder.build(param);

            // TODO[jsse] Use the resulting chain for post-validation checks instead of the input chain?

            /*
             * TODO[jsse] Determine 'chainsToPublicCA' based on the trust anchor for the result
             * chain. SunJSSE appears to consider this to be any trusted cert in original-location
             * cacerts file with alias.contains(" [jdk")
             */
//            X509Certificate taCert = result.getTrustAnchor().getTrustedCert();
        }
        catch (GeneralSecurityException e)
        {
            throw new CertificateException("unable to process certificates: " + e.getMessage(), e);
        }
    }

    static void checkExtendedTrust(X509Certificate[] chain, String authType, Socket socket, boolean isServer)
        throws CertificateException
    {
        if (socket instanceof SSLSocket && socket.isConnected())
        {
            SSLSocket sslSocket = (SSLSocket)socket;
            BCExtendedSSLSession sslSession = getHandshakeSession(sslSocket);
            BCSSLParameters sslParameters = getSSLParameters(sslSocket);
            checkExtendedTrust(chain, authType, isServer, sslSession, sslParameters);
        }
    }

    static void checkExtendedTrust(X509Certificate[] chain, String authType, SSLEngine engine, boolean isServer)
        throws CertificateException
    {
        if (null != engine)
        {
            BCExtendedSSLSession sslSession = getHandshakeSession(engine);
            BCSSLParameters sslParameters = getSSLParameters(engine);
            checkExtendedTrust(chain, authType, isServer, sslSession, sslParameters);
        }
    }

    private static void checkExtendedTrust(X509Certificate[] chain, String authType, boolean isServer,
        BCExtendedSSLSession sslSession, BCSSLParameters sslParameters) throws CertificateException
    {
        String endpointIDAlg = sslParameters.getEndpointIdentificationAlgorithm();
        if (null != endpointIDAlg && endpointIDAlg.length() > 0)
        {
            checkEndpointID(chain[0], endpointIDAlg, isServer, sslSession);
        }

        // TODO[jsse] SunJSSE also does some AlgorithmConstraints-related checks here. 
    }

    private static void checkEndpointID(X509Certificate certificate, String endpointIDAlg, boolean isServer,
        BCExtendedSSLSession sslSession) throws CertificateException
    {
        String peerHost = sslSession.getPeerHost();
        if (isServer)
        {
            BCSNIHostName sniHostName = getSNIHostName(sslSession);
            if (null != sniHostName)
            {
                String hostname = sniHostName.getAsciiName();
                if (!hostname.equalsIgnoreCase(peerHost))
                {
                    try
                    {
                        checkEndpointID(hostname, certificate, endpointIDAlg);
                        return;
                    }
                    catch (CertificateException e)
                    {
                        // ignore (log only) and continue on to check 'peerHost' instead
                        LOG.log(Level.FINE, "Server's endpoint ID did not match the SNI host_name: " + hostname, e);
                    }
                }
            }
        }

        checkEndpointID(peerHost, certificate, endpointIDAlg);
    }

    private static void checkEndpointID(String hostname, X509Certificate certificate, String endpointIDAlg)
        throws CertificateException
    {
        // Strip "[]" off IPv6 addresses
        hostname = JsseUtils.stripSquareBrackets(hostname);

        if (endpointIDAlg.equalsIgnoreCase("HTTPS"))
        {
            HostnameUtil.checkHostname(hostname, certificate, true);
        }
        else if (endpointIDAlg.equalsIgnoreCase("LDAP") || endpointIDAlg.equalsIgnoreCase("LDAPS"))
        {
            HostnameUtil.checkHostname(hostname, certificate, false);
        }
        else
        {
            throw new CertificateException("Unknown endpoint ID algorithm: " + endpointIDAlg);
        }
    }

    private static BCSNIHostName getSNIHostName(BCExtendedSSLSession sslSession)
    {
        List<BCSNIServerName> serverNames = sslSession.getRequestedServerNames();
        if (null != serverNames)
        {
            for (BCSNIServerName serverName : serverNames)
            {
                if (null != serverName && BCStandardConstants.SNI_HOST_NAME == serverName.getType())
                {
                    if (serverName instanceof BCSNIHostName)
                    {
                        return (BCSNIHostName)serverName;
                    }

                    try
                    {
                        return new BCSNIHostName(serverName.getEncoded());
                    }
                    catch (RuntimeException e)
                    {
                        return null;
                    }
                }
            }
        }
        return null;
    }

    private static BCExtendedSSLSession getHandshakeSession(SSLEngine sslEngine) throws CertificateException
    {
        BCExtendedSSLSession handshakeSession = SSLEngineUtil.importHandshakeSession(sslEngine);
        if (null == handshakeSession)
        {
            throw new CertificateException("No handshake session for engine");
        }
        return handshakeSession;
    }

    private static BCExtendedSSLSession getHandshakeSession(SSLSocket sslSocket) throws CertificateException
    {
        BCExtendedSSLSession handshakeSession = SSLSocketUtil.importHandshakeSession(sslSocket);
        if (null == handshakeSession)
        {
            throw new CertificateException("No handshake session for socket");
        }
        return handshakeSession;
    }

    private static BCSSLParameters getSSLParameters(SSLEngine sslEngine) throws CertificateException
    {
        BCSSLParameters sslParameters = SSLEngineUtil.importSSLParameters(sslEngine);
        if (null == sslParameters)
        {
            throw new CertificateException("No SSL parameters for engine");
        }
        return sslParameters;
    }

    private static BCSSLParameters getSSLParameters(SSLSocket sslSocket) throws CertificateException
    {
        BCSSLParameters sslParameters = SSLSocketUtil.importSSLParameters(sslSocket);
        if (null == sslParameters)
        {
            throw new CertificateException("No SSL parameters for socket");
        }
        return sslParameters;
    }
}
