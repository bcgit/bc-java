package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertSelector;
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
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCX509ExtendedTrustManager;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.tls.KeyExchangeAlgorithm;

class ProvX509TrustManager
    extends BCX509ExtendedTrustManager
{
    private static final Logger LOG = Logger.getLogger(ProvX509TrustManager.class.getName());

    private static final boolean provCheckRevocation = PropertyUtils
        .getBooleanSystemProperty("com.sun.net.ssl.checkRevocation", false);
    private static final boolean provTrustManagerCheckEKU = PropertyUtils
        .getBooleanSystemProperty("org.bouncycastle.jsse.trustManager.checkEKU", true);

    private static final Map<String, Integer> keyUsagesServer = createKeyUsagesServer();

    private static void addKeyUsageServer(Map<String, Integer> keyUsages, int keyUsage, int... keyExchangeAlgorithms)
    {
        for (int keyExchangeAlgorithm : keyExchangeAlgorithms)
        {
            String authType = JsseUtils.getAuthTypeServer(keyExchangeAlgorithm);

            if (null != keyUsages.put(authType, keyUsage))
            {
                throw new IllegalStateException("Duplicate keys in server key usages");
            }
        }
    }

    private static Map<String, Integer> createKeyUsagesServer()
    {
        Map<String, Integer> keyUsages = new HashMap<String, Integer>();

        addKeyUsageServer(keyUsages, ProvAlgorithmChecker.KU_DIGITAL_SIGNATURE, KeyExchangeAlgorithm.DHE_DSS,
            KeyExchangeAlgorithm.DHE_RSA, KeyExchangeAlgorithm.ECDHE_ECDSA, KeyExchangeAlgorithm.ECDHE_RSA,
            KeyExchangeAlgorithm.NULL);

        addKeyUsageServer(keyUsages, ProvAlgorithmChecker.KU_KEY_ENCIPHERMENT, KeyExchangeAlgorithm.RSA);

        addKeyUsageServer(keyUsages, ProvAlgorithmChecker.KU_KEY_AGREEMENT, KeyExchangeAlgorithm.DH_DSS,
            KeyExchangeAlgorithm.DH_RSA, KeyExchangeAlgorithm.ECDH_ECDSA, KeyExchangeAlgorithm.ECDH_RSA);

        return Collections.unmodifiableMap(keyUsages);
    }

    private final boolean isInFipsMode;
    private final JcaJceHelper helper;
    private final Set<X509Certificate> trustedCerts;
    private final PKIXBuilderParameters pkixParametersTemplate;
    private final X509TrustManager exportX509TrustManager;

    ProvX509TrustManager(boolean isInFipsMode, JcaJceHelper helper, Set<TrustAnchor> trustAnchors)
        throws InvalidAlgorithmParameterException
    {
        this.isInFipsMode = isInFipsMode;
        this.helper = helper;
        this.trustedCerts = getTrustedCerts(trustAnchors);

        // Setup PKIX parameters
        if (trustedCerts.isEmpty())
        {
            this.pkixParametersTemplate = null;
        }
        else
        {
            this.pkixParametersTemplate = new PKIXBuilderParameters(trustAnchors, null);
            this.pkixParametersTemplate.setRevocationEnabled(provCheckRevocation);
        }

        this.exportX509TrustManager = X509TrustManagerUtil.exportX509TrustManager(this);
    }

    ProvX509TrustManager(boolean isInFipsMode, JcaJceHelper helper, PKIXParameters baseParameters)
        throws InvalidAlgorithmParameterException
    {
        this.isInFipsMode = isInFipsMode;
        this.helper = helper;
        this.trustedCerts = getTrustedCerts(baseParameters.getTrustAnchors());

        // Setup PKIX parameters
        if (trustedCerts.isEmpty())
        {
            this.pkixParametersTemplate = null;
        }
        else if (baseParameters instanceof PKIXBuilderParameters)
        {
            this.pkixParametersTemplate = (PKIXBuilderParameters)baseParameters;
        }
        else
        {
            this.pkixParametersTemplate = new PKIXBuilderParameters(baseParameters.getTrustAnchors(), null);
            this.pkixParametersTemplate.setAnyPolicyInhibited(baseParameters.isAnyPolicyInhibited());
            this.pkixParametersTemplate.setCertPathCheckers(baseParameters.getCertPathCheckers());
            this.pkixParametersTemplate.setCertStores(baseParameters.getCertStores());
            this.pkixParametersTemplate.setDate(baseParameters.getDate());
            this.pkixParametersTemplate.setExplicitPolicyRequired(baseParameters.isExplicitPolicyRequired());
            this.pkixParametersTemplate.setInitialPolicies(baseParameters.getInitialPolicies());
            this.pkixParametersTemplate.setPolicyMappingInhibited(baseParameters.isPolicyMappingInhibited());
            this.pkixParametersTemplate.setPolicyQualifiersRejected(baseParameters.getPolicyQualifiersRejected());
            this.pkixParametersTemplate.setRevocationEnabled(baseParameters.isRevocationEnabled());
            this.pkixParametersTemplate.setSigProvider(baseParameters.getSigProvider());
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
        checkTrusted(chain, authType, null, false);
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
        throws CertificateException
    {
        checkTrusted(chain, authType, TransportData.from(socket), false);
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
        throws CertificateException
    {
        checkTrusted(chain, authType, TransportData.from(engine), false);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType)
        throws CertificateException
    {
        checkTrusted(chain, authType, null, true);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
        throws CertificateException
    {
        checkTrusted(chain, authType, TransportData.from(socket), true);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
        throws CertificateException
    {
        checkTrusted(chain, authType, TransportData.from(engine), true);
    }

    public X509Certificate[] getAcceptedIssuers()
    {
        return trustedCerts.toArray(new X509Certificate[trustedCerts.size()]);
    }

    private X509Certificate[] buildCertPath(X509Certificate[] chain, BCAlgorithmConstraints algorithmConstraints,
        List<byte[]> statusResponses) throws GeneralSecurityException
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

        // TODO Can we cache the CertificateFactory instance?
        CertificateFactory certificateFactory = helper.createCertificateFactory("X.509");
        Provider pkixProvider = certificateFactory.getProvider();

        CertStoreParameters certStoreParameters = getCertStoreParameters(eeCert, chain);
        CertStore certStore;
        try
        {
            certStore = CertStore.getInstance("Collection", certStoreParameters, pkixProvider);
        }
        catch (GeneralSecurityException e)
        {
            certStore = CertStore.getInstance("Collection", certStoreParameters);
        }

        CertPathBuilder pkixBuilder;
        try
        {
            pkixBuilder = CertPathBuilder.getInstance("PKIX", pkixProvider);
        }
        catch (NoSuchAlgorithmException e)
        {
            pkixBuilder = CertPathBuilder.getInstance("PKIX");
        }

        PKIXBuilderParameters pkixParameters = (PKIXBuilderParameters)pkixParametersTemplate.clone();
        pkixParameters.addCertPathChecker(new ProvAlgorithmChecker(isInFipsMode, helper, algorithmConstraints));
        pkixParameters.addCertStore(certStore);
        pkixParameters.setTargetCertConstraints(
            createTargetCertConstraints(eeCert, pkixParameters.getTargetCertConstraints()));

        if (!statusResponses.isEmpty())
        {
            addStatusResponses(pkixBuilder, pkixParameters, chain, statusResponses);
        }

        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)pkixBuilder.build(pkixParameters);

        /*
         * TODO[jsse] Determine 'chainsToPublicCA' based on the trust anchor for the result
         * chain. SunJSSE appears to consider this to be any trusted cert in original-location
         * cacerts file with alias.contains(" [jdk")
         */
        return getTrustedChain(result.getCertPath(), result.getTrustAnchor());
    }

    private void checkTrusted(X509Certificate[] chain, String authType, TransportData transportData,
        boolean checkServerTrusted) throws CertificateException
    {
        if (null == chain || chain.length < 1)
        {
            throw new IllegalArgumentException("'chain' must be a chain of at least one certificate");
        }
        if (null == authType || authType.length() < 1)
        {
            throw new IllegalArgumentException("'authType' must be a non-null, non-empty string");
        }

        if (null == pkixParametersTemplate)
        {
            throw new CertificateException("Unable to build a CertPath: no PKIXBuilderParameters available");
        }

        X509Certificate[] trustedChain = validateChain(chain, authType, transportData, checkServerTrusted);

        checkExtendedTrust(trustedChain, authType, transportData, checkServerTrusted);
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
        return new CollectionCertStoreParameters(Collections.unmodifiableCollection(certs));
    }

    private X509Certificate[] validateChain(X509Certificate[] chain, String authType, TransportData transportData,
        boolean checkServerTrusted) throws CertificateException
    {
        try
        {
            BCAlgorithmConstraints algorithmConstraints = TransportData.getAlgorithmConstraints(transportData, false);
            List<byte[]> statusResponses = TransportData.getStatusResponses(transportData);

            X509Certificate[] trustedChain = buildCertPath(chain, algorithmConstraints, statusResponses);

            KeyPurposeId ekuOID = getRequiredExtendedKeyUsage(checkServerTrusted);
            int kuBit = getRequiredKeyUsage(checkServerTrusted, authType);

            ProvAlgorithmChecker.checkCertPathExtras(helper, algorithmConstraints, trustedChain, ekuOID, kuBit);

            // TODO[jsse] Consider supporting jdk.security.caDistrustPolicies security property

            return trustedChain;
        }
        catch (GeneralSecurityException e)
        {
            throw new CertificateException("Unable to construct a valid chain", e);
        }
    }

    static void checkEndpointID(String hostname, X509Certificate certificate, String endpointIDAlg)
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

    static void checkExtendedTrust(X509Certificate[] trustedChain, String authType, TransportData transportData,
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
    }

    static KeyPurposeId getRequiredExtendedKeyUsage(boolean forServer)
    {
        return !provTrustManagerCheckEKU
            ?   null
            :   forServer
            ?   KeyPurposeId.id_kp_serverAuth
            :   KeyPurposeId.id_kp_clientAuth;
    }

    static int getRequiredKeyUsage(boolean checkServerTrusted, String authType)
        throws CertificateException
    {
        if (!checkServerTrusted)
        {
            return ProvAlgorithmChecker.KU_DIGITAL_SIGNATURE;
        }

        Integer requiredKeyUsage = keyUsagesServer.get(authType);
        if (null == requiredKeyUsage)
        {
            throw new CertificateException("Unsupported server authType: " + authType);
        }

        return requiredKeyUsage.intValue();
    }

    private static void addStatusResponses(CertPathBuilder pkixBuilder, PKIXBuilderParameters pkixParameters,
        X509Certificate[] chain, List<byte[]> statusResponses)
    {
        Map<X509Certificate, byte[]> statusResponseMap = new HashMap<X509Certificate, byte[]>();
        int count = Math.min(chain.length, statusResponses.size());
        for (int i = 0; i < count; ++i)
        {
            byte[] statusResponse = statusResponses.get(i);
            if (null != statusResponse && statusResponse.length > 0)
            {
                X509Certificate certificate = chain[i];

                // TODO[jsse] putIfAbsent from JDK 8
                if (!statusResponseMap.containsKey(certificate))
                {
                    statusResponseMap.put(certificate, statusResponse);
                }
            }
        }

        if (!statusResponseMap.isEmpty())
        {
            try
            {
                PKIXUtil.addStatusResponses(pkixBuilder, pkixParameters, statusResponseMap);
            }
            catch (RuntimeException e)
            {
                // Use of the status responses is an optional optimization
                LOG.log(Level.FINE, "Failed to add status responses for revocation checking", e);
            }
        }
    }

    private static void checkEndpointID(X509Certificate certificate, String endpointIDAlg, boolean checkServerTrusted,
        BCExtendedSSLSession sslSession) throws CertificateException
    {
        String peerHost = sslSession.getPeerHost();
        if (checkServerTrusted)
        {
            BCSNIHostName sniHostName = JsseUtils.getSNIHostName(sslSession.getRequestedServerNames());
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

    private static X509CertSelector createTargetCertConstraints(final X509Certificate eeCert,
        final CertSelector userConstraints)
    {
        return new X509CertSelector()
        {
            {
                setCertificate(eeCert);
            }

            @Override
            public boolean match(Certificate cert)
            {
                return super.match(cert) && (null == userConstraints || userConstraints.match(cert));
            }
        };
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
