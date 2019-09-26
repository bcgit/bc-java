package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Provider;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.jcajce.util.JcaJceHelper;
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

    private static final boolean provCheckRevocation = PropertyUtils
        .getBooleanSystemProperty("com.sun.net.ssl.checkRevocation", false);

    private final JcaJceHelper helper;
    private final Set<X509Certificate> trustedCerts;
    private final PKIXParameters baseParameters;
    private final X509TrustManager exportX509TrustManager;

    ProvX509TrustManager(JcaJceHelper helper, Set<TrustAnchor> trustAnchors)
        throws InvalidAlgorithmParameterException
    {
        this.helper = helper;
        this.trustedCerts = getTrustedCerts(trustAnchors);

        // Setup PKIX parameters
        {
            this.baseParameters = new PKIXBuilderParameters(trustAnchors, null);
            this.baseParameters.setRevocationEnabled(provCheckRevocation);
        }

        this.exportX509TrustManager = X509TrustManagerUtil.exportX509TrustManager(this);
    }

    ProvX509TrustManager(JcaJceHelper helper, PKIXParameters baseParameters)
        throws InvalidAlgorithmParameterException
    {
        this.helper = helper;
        this.trustedCerts = getTrustedCerts(baseParameters.getTrustAnchors());

        // Setup PKIX parameters
        {
            if (baseParameters instanceof PKIXBuilderParameters)
            {
                this.baseParameters = (PKIXBuilderParameters)baseParameters.clone();
                this.baseParameters.setTargetCertConstraints(null);
            }
            else
            {
                this.baseParameters = new PKIXBuilderParameters(baseParameters.getTrustAnchors(), null);
                this.baseParameters.setAnyPolicyInhibited(baseParameters.isAnyPolicyInhibited());
                this.baseParameters.setCertPathCheckers(baseParameters.getCertPathCheckers());
                this.baseParameters.setCertStores(baseParameters.getCertStores());
                this.baseParameters.setDate(baseParameters.getDate());
                this.baseParameters.setExplicitPolicyRequired(baseParameters.isExplicitPolicyRequired());
                this.baseParameters.setInitialPolicies(baseParameters.getInitialPolicies());
                this.baseParameters.setPolicyMappingInhibited(baseParameters.isPolicyMappingInhibited());
                this.baseParameters.setPolicyQualifiersRejected(baseParameters.getPolicyQualifiersRejected());
                this.baseParameters.setRevocationEnabled(baseParameters.isRevocationEnabled());
                this.baseParameters.setSigProvider(baseParameters.getSigProvider());
            }
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

    private void checkTrusted(X509Certificate[] chain, String authType, Socket socket, boolean checkServerTrusted)
        throws CertificateException
    {
        X509Certificate[] trustedChain = validateChain(chain, authType, checkServerTrusted);

        checkExtendedTrust(trustedChain, authType, socket, checkServerTrusted);
    }

    private void checkTrusted(X509Certificate[] chain, String authType, SSLEngine engine, boolean checkServerTrusted)
        throws CertificateException
    {
        X509Certificate[] trustedChain = validateChain(chain, authType, checkServerTrusted);

        checkExtendedTrust(trustedChain, authType, engine, checkServerTrusted);
    }

    // NOTE: We avoid re-reading eeCert from chain[0]
    private CertStoreParameters getCertStoreParameters(X509Certificate eeCert, X509Certificate[] chain)
    {
        ArrayList<X509Certificate> certs = new ArrayList<X509Certificate>(chain.length);
        certs.add(eeCert);
        for (int i = 1; i < chain.length; ++i)
        {
            if (!trustedCerts.contains(chain[i]))
            {
                certs.add(chain[i]);
            }
        }
        return new CollectionCertStoreParameters(certs);   
    }

    private X509Certificate[] validateChain(X509Certificate[] chain, String authType, boolean checkServerTrusted)
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
//        String validationAuthType = checkServerTrusted ? authType : null;

        /*
         * RFC 8446 4.4.2 "For maximum compatibility, all implementations SHOULD be prepared to
         * handle potentially extraneous certificates and arbitrary orderings from any TLS version,
         * with the exception of the end-entity certificate which MUST be first."
         */
        X509Certificate eeCert = chain[0];
        if (trustedCerts.contains(eeCert))
        {
            return new X509Certificate[]{ eeCert };
        }

        try
        {
            /*
             * TODO[jsse] When 'checkServerTrusted', make use of any status responses (OCSP) via
             * BCExtendedSSLSession.getStatusResponses()
             */

            // TODO Can we cache the CertificateFactory instance?
            CertificateFactory certificateFactory = helper.createCertificateFactory("X.509");
            Provider pkixProvider = certificateFactory.getProvider();

            CertStoreParameters certStoreParameters = getCertStoreParameters(eeCert, chain);
            CertStore certStore = CertStore.getInstance("Collection", certStoreParameters, pkixProvider);

            X509CertSelector certSelector = new X509CertSelector();
            certSelector.setCertificate(eeCert);

            PKIXBuilderParameters certPathParameters = (PKIXBuilderParameters)baseParameters.clone();
            certPathParameters.addCertStore(certStore);
            certPathParameters.setTargetCertConstraints(certSelector);

            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", pkixProvider);
            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(certPathParameters);

            /*
             * TODO[jsse] Determine 'chainsToPublicCA' based on the trust anchor for the result
             * chain. SunJSSE appears to consider this to be any trusted cert in original-location
             * cacerts file with alias.contains(" [jdk")
             */
            return getTrustedChain(result.getCertPath(), result.getTrustAnchor());
        }
        catch (GeneralSecurityException e)
        {
            throw new CertificateException("unable to process certificates: " + e.getMessage(), e);
        }
    }

    static void checkExtendedTrust(X509Certificate[] trustedChain, String authType, Socket socket,
        boolean checkServerTrusted) throws CertificateException
    {
        if (socket instanceof SSLSocket && socket.isConnected())
        {
            SSLSocket sslSocket = (SSLSocket)socket;
            BCExtendedSSLSession sslSession = getHandshakeSession(sslSocket);
            BCSSLParameters sslParameters = getSSLParameters(sslSocket);
            checkExtendedTrust(trustedChain, authType, checkServerTrusted, sslSession, sslParameters);
        }
    }

    static void checkExtendedTrust(X509Certificate[] trustedChain, String authType, SSLEngine engine,
        boolean checkServerTrusted) throws CertificateException
    {
        if (null != engine)
        {
            BCExtendedSSLSession sslSession = getHandshakeSession(engine);
            BCSSLParameters sslParameters = getSSLParameters(engine);
            checkExtendedTrust(trustedChain, authType, checkServerTrusted, sslSession, sslParameters);
        }
    }

    private static void checkExtendedTrust(X509Certificate[] trustedChain, String authType, boolean checkServerTrusted,
        BCExtendedSSLSession sslSession, BCSSLParameters sslParameters) throws CertificateException
    {
        String endpointIDAlg = sslParameters.getEndpointIdentificationAlgorithm();
        if (null != endpointIDAlg && endpointIDAlg.length() > 0)
        {
            checkEndpointID(trustedChain[0], endpointIDAlg, checkServerTrusted, sslSession);
        }

        // TODO[jsse] SunJSSE also does some AlgorithmConstraints-related checks here. 
    }

    private static void checkEndpointID(X509Certificate certificate, String endpointIDAlg, boolean checkServerTrusted,
        BCExtendedSSLSession sslSession) throws CertificateException
    {
        String peerHost = sslSession.getPeerHost();
        if (checkServerTrusted)
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

    private static X509Certificate getTrustedCert(TrustAnchor trustAnchor) throws CertificateException
    {
        X509Certificate trustedCert = trustAnchor.getTrustedCert();
        if (null == trustedCert)
        {
            throw new CertificateException("No certificate for TrustAnchor");
        }
        return trustedCert;
    }

    private static Set<X509Certificate> getTrustedCerts(Set<TrustAnchor> trustAnchors)
    {
        Set<X509Certificate> result = new HashSet<X509Certificate>(trustAnchors.size());
        for (TrustAnchor trustAnchor : trustAnchors)
        {
            if (null != trustAnchor)
            {
                X509Certificate trustedCert = trustAnchor.getTrustedCert();
                if (null != trustedCert)
                {
                    result.add(trustedCert);
                }
            }
        }
        return result;
    }

    private static X509Certificate[] getTrustedChain(CertPath certPath, TrustAnchor trustAnchor)
        throws CertificateException
    {
        List<? extends Certificate> certificates = certPath.getCertificates();
        X509Certificate[] result = new X509Certificate[certificates.size() + 1];
        certificates.toArray(result);
        result[result.length - 1] = getTrustedCert(trustAnchor);
        return result;
    }
}
