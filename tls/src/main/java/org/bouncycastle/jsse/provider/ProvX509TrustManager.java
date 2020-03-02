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
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.asn1.x509.KeyPurposeId;
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

    private static final int KU_DIGITAL_SIGNATURE = 0;
    private static final int KU_KEY_ENCIPHERMENT = 2;
    private static final int KU_KEY_AGREEMENT = 4;

    private static final Map<String, Integer> serverKeyUsageMap = createServerKeyUsageMap();

    private static Map<String, Integer> createServerKeyUsageMap()
    {
        Map<String, Integer> kus = new HashMap<String, Integer>();

        kus.put("DHE_DSS", KU_DIGITAL_SIGNATURE);
        kus.put("DHE_RSA", KU_DIGITAL_SIGNATURE);
        kus.put("ECDHE_ECDSA", KU_DIGITAL_SIGNATURE);
        kus.put("ECDHE_RSA", KU_DIGITAL_SIGNATURE);
        kus.put("UNKNOWN", KU_DIGITAL_SIGNATURE);  // TLS 1.3

        kus.put("RSA", KU_KEY_ENCIPHERMENT);

        kus.put("DH_DSS", KU_KEY_AGREEMENT);
        kus.put("DH_RSA", KU_KEY_AGREEMENT);
        kus.put("ECDH_ECDSA", KU_KEY_AGREEMENT);
        kus.put("ECDH_RSA", KU_KEY_AGREEMENT);

        return Collections.unmodifiableMap(kus);
    }

    private final JcaJceHelper helper;
    private final Set<X509Certificate> trustedCerts;
    private final PKIXBuilderParameters baseParameters;
    private final X509TrustManager exportX509TrustManager;

    ProvX509TrustManager(JcaJceHelper helper, Set<TrustAnchor> trustAnchors)
        throws InvalidAlgorithmParameterException
    {
        this.helper = helper;
        this.trustedCerts = getTrustedCerts(trustAnchors);

        // Setup PKIX parameters
        if (trustedCerts.isEmpty())
        {
            this.baseParameters = null;
        }
        else
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
        if (trustedCerts.isEmpty())
        {
            this.baseParameters = null;
        }
        else if (baseParameters instanceof PKIXBuilderParameters)
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

    private X509Certificate[] buildCertPath(X509Certificate[] chain) throws CertificateException
    {
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

        if (null == baseParameters)
        {
            throw new CertificateException("unable to process certificates: no PKIXBuilderParameters available");
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

        X509Certificate[] trustedChain = buildCertPath(chain);

        String validationAuthType = checkServerTrusted ? authType : null;
        checkEndEntity(trustedChain, validationAuthType, checkServerTrusted);

        return trustedChain;
    }

    static void checkEndEntity(X509Certificate[] trustedChain, String authType, boolean checkServerTrusted)
        throws CertificateException
    {
        // These checks not needed for a trust anchor
        if (trustedChain.length > 1)
        {
            X509Certificate endEntity = trustedChain[0];

            if (checkServerTrusted)
            {
                Integer requiredKeyUsage = serverKeyUsageMap.get(authType);
                if (null == requiredKeyUsage)
                {
                    throw new CertificateException("Unsupported server authType: " + authType);
                }

                checkKeyUsage(endEntity, requiredKeyUsage.intValue());

                checkExtendedKeyUsage(endEntity, KeyPurposeId.id_kp_serverAuth);
            }
            else
            {
                checkKeyUsage(endEntity, KU_DIGITAL_SIGNATURE);

                checkExtendedKeyUsage(endEntity, KeyPurposeId.id_kp_clientAuth);
            }

            // TODO[jsse] Consider supporting jdk.security.caDistrustPolicies security property
        }
    }

    static void checkExtendedKeyUsage(X509Certificate certificate, KeyPurposeId ekuOID) throws CertificateException
    {
        if (!supportsExtendedKeyUsage(certificate, ekuOID))
        {
            throw new CertificateException("Certificate doesn't support '" + ekuOID + "' ExtendedKeyUsage");
        }
    }

    static void checkExtendedTrust(X509Certificate[] trustedChain, String authType, Socket socket,
        boolean checkServerTrusted) throws CertificateException
    {
        checkExtendedTrust(trustedChain, authType, TransportData.from(socket), checkServerTrusted);
    }

    static void checkExtendedTrust(X509Certificate[] trustedChain, String authType, SSLEngine engine,
        boolean checkServerTrusted) throws CertificateException
    {
        checkExtendedTrust(trustedChain, authType, TransportData.from(engine), checkServerTrusted);
    }

    private static void checkExtendedTrust(X509Certificate[] trustedChain, String authType, TransportData transportData,
        boolean checkServerTrusted) throws CertificateException
    {
        if (null != transportData)
        {
            BCSSLParameters parameters = transportData.getParameters();

            String endpointIDAlg = parameters.getEndpointIdentificationAlgorithm();
            if (null != endpointIDAlg && endpointIDAlg.length() > 0)
            {
                BCExtendedSSLSession handshakeSession = transportData.getHandshakeSession();
                if (null == handshakeSession)
                {
                    throw new CertificateException("No handshake session");
                }

                checkEndpointID(trustedChain[0], endpointIDAlg, checkServerTrusted, handshakeSession);
            }
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

    private static void checkKeyUsage(X509Certificate certificate, int kuBit) throws CertificateException
    {
        if (!supportsKeyUsage(certificate, kuBit))
        {
            throw new CertificateException("Certificate doesn't support '" + getKeyUsageName(kuBit) + "' KeyUsage");
        }
    }

    private static String getKeyUsageName(int kuBit)
    {
        switch (kuBit)
        {
        case KU_DIGITAL_SIGNATURE:
            return "digitalSignature";
        case KU_KEY_ENCIPHERMENT:
            return "keyEncipherment";
        case KU_KEY_AGREEMENT:
            return "keyAgreement";
        default:
            return "(" + kuBit + ")";
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

    private static boolean supportsExtendedKeyUsage(X509Certificate certificate, KeyPurposeId ekuOID)
        throws CertificateException
    {
        List<String> eku = certificate.getExtendedKeyUsage();

        return null == eku || eku.contains(ekuOID.getId()) || eku.contains(KeyPurposeId.anyExtendedKeyUsage.getId()); 
    }

    private static boolean supportsKeyUsage(X509Certificate certificate, int kuBit)
    {
        boolean[] ku = certificate.getKeyUsage();

        return null == ku || (ku.length > kuBit && ku[kuBit]);
    }
}
