package org.bouncycastle.jsse.provider;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.SignatureScheme;

abstract class FipsUtils
{
    /*
     * This can only be set to true if the underlying provider is able to assert it is compliant with
     * FIPS IG A.5 and a mechanism has been integrated into this API accordingly to ensure that is the
     * case.
     */
    private static final boolean provAllowGCMCiphers = false;

    private static final boolean provAllowRSAKeyExchange = PropertyUtils
        .getBooleanSystemProperty("org.bouncycastle.jsse.fips.allowRSAKeyExchange", true);

    private static final Set<String> FIPS_SUPPORTED_CIPHERSUITES = createFipsSupportedCipherSuites();
    private static final Set<String> FIPS_SUPPORTED_PROTOCOLS = createFipsSupportedProtocols();

    private static Set<String> createFipsSupportedCipherSuites()
    {
        /*
         * Cipher suite list current as of NIST SP 800-52 Revision 2.
         * 
         * Static (EC)DH cipher suites commented out since not supported by BCJSSE.
         * 
         * PSK cipher suites from Appendix C left out completely since the BCJSSE provider does not
         * currently support _any_ PSK key exchange methods.
         */
        final Set<String> cs = new HashSet<String>();

        cs.add("TLS_AES_128_CCM_8_SHA256");
        cs.add("TLS_AES_128_CCM_SHA256");

//        cs.add("TLS_DH_DSS_WITH_AES_128_CBC_SHA");
//        cs.add("TLS_DH_DSS_WITH_AES_128_CBC_SHA256");
//        cs.add("TLS_DH_DSS_WITH_AES_256_CBC_SHA");
//        cs.add("TLS_DH_DSS_WITH_AES_256_CBC_SHA256");

//        cs.add("TLS_DH_RSA_WITH_AES_128_CBC_SHA");
//        cs.add("TLS_DH_RSA_WITH_AES_128_CBC_SHA256");
//        cs.add("TLS_DH_RSA_WITH_AES_256_CBC_SHA");
//        cs.add("TLS_DH_RSA_WITH_AES_256_CBC_SHA256");

        cs.add("TLS_DHE_DSS_WITH_AES_128_CBC_SHA");
        cs.add("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_DHE_DSS_WITH_AES_256_CBC_SHA");
        cs.add("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256");

        cs.add("TLS_DHE_RSA_WITH_AES_128_CBC_SHA");
        cs.add("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_DHE_RSA_WITH_AES_128_CCM");
        cs.add("TLS_DHE_RSA_WITH_AES_128_CCM_8");
        cs.add("TLS_DHE_RSA_WITH_AES_256_CBC_SHA");
        cs.add("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256");
        cs.add("TLS_DHE_RSA_WITH_AES_256_CCM");
        cs.add("TLS_DHE_RSA_WITH_AES_256_CCM_8");

//        cs.add("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA");
//        cs.add("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256");
//        cs.add("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA");
//        cs.add("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384");

//        cs.add("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA");
//        cs.add("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256");
//        cs.add("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA");
//        cs.add("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384");

        cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_CCM");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_CCM");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8");

        cs.add("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        cs.add("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
        cs.add("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384");

        if (provAllowGCMCiphers)
        {
            cs.add("TLS_AES_128_GCM_SHA256");
            cs.add("TLS_AES_256_GCM_SHA384");

//            cs.add("TLS_DH_DSS_WITH_AES_128_GCM_SHA256");
//            cs.add("TLS_DH_DSS_WITH_AES_256_GCM_SHA384");

//            cs.add("TLS_DH_RSA_WITH_AES_128_GCM_SHA256");
//            cs.add("TLS_DH_RSA_WITH_AES_256_GCM_SHA384");

            cs.add("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256");
            cs.add("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384");

            cs.add("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256");
            cs.add("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384");

//            cs.add("TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256");
//            cs.add("TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384");

//            cs.add("TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256");
//            cs.add("TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384");

            cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
            cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");

            cs.add("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
            cs.add("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        }

        if (provAllowRSAKeyExchange)
        {
            cs.add("TLS_RSA_WITH_AES_128_CBC_SHA");
            cs.add("TLS_RSA_WITH_AES_128_CBC_SHA256");
            cs.add("TLS_RSA_WITH_AES_128_CCM");
            cs.add("TLS_RSA_WITH_AES_128_CCM_8");
            cs.add("TLS_RSA_WITH_AES_256_CBC_SHA");
            cs.add("TLS_RSA_WITH_AES_256_CBC_SHA256");
            cs.add("TLS_RSA_WITH_AES_256_CCM");
            cs.add("TLS_RSA_WITH_AES_256_CCM_8");

            if (provAllowGCMCiphers)
            {
                cs.add("TLS_RSA_WITH_AES_128_GCM_SHA256");
                cs.add("TLS_RSA_WITH_AES_256_GCM_SHA384");
            }
        }

        return Collections.unmodifiableSet(cs);
    }

    private static Set<String> createFipsSupportedProtocols()
    {
        final Set<String> ps = new HashSet<String>();

        ps.add("TLSv1");
        ps.add("TLSv1.1");
        ps.add("TLSv1.2");
        ps.add("TLSv1.3");

        return Collections.unmodifiableSet(ps);
    }

    static boolean isFipsCipherSuite(String cipherSuite)
    {
        return cipherSuite != null && FIPS_SUPPORTED_CIPHERSUITES.contains(cipherSuite);
    }

    static boolean isFipsNamedGroup(int namedGroup)
    {
        /*
         * NOTE: NIST SP 800-56A Revision 3 Appendix D lists several more SEC curves, however they
         * are all obsolete as of TLS 1.3.
         */
        switch (namedGroup)
        {
        case NamedGroup.secp256r1:
        case NamedGroup.secp384r1:
        case NamedGroup.secp521r1:
        case NamedGroup.ffdhe2048:
        case NamedGroup.ffdhe3072:
        case NamedGroup.ffdhe4096:
        case NamedGroup.ffdhe6144:
        case NamedGroup.ffdhe8192:
            return true;

        case NamedGroup.x25519:
        case NamedGroup.x448:
        default:
            return false;
        }
    }

    static boolean isFipsProtocol(String protocol)
    {
        return protocol != null && FIPS_SUPPORTED_PROTOCOLS.contains(protocol);
    }

    static boolean isFipsSignatureScheme(int signatureScheme)
    {
        switch (signatureScheme)
        {
        case SignatureSchemeInfo.historical_dsa_sha1:
        case SignatureSchemeInfo.historical_dsa_sha224:
        case SignatureSchemeInfo.historical_dsa_sha256:
        case SignatureScheme.ecdsa_sha1:
        case SignatureSchemeInfo.historical_ecdsa_sha224:
        case SignatureScheme.ecdsa_secp256r1_sha256:
        case SignatureScheme.ecdsa_secp384r1_sha384:
        case SignatureScheme.ecdsa_secp521r1_sha512:
        case SignatureScheme.rsa_pkcs1_sha1:
        case SignatureSchemeInfo.historical_rsa_sha224:
        case SignatureScheme.rsa_pkcs1_sha256:
        case SignatureScheme.rsa_pkcs1_sha384:
        case SignatureScheme.rsa_pkcs1_sha512:
        case SignatureScheme.rsa_pss_pss_sha256:
        case SignatureScheme.rsa_pss_pss_sha384:
        case SignatureScheme.rsa_pss_pss_sha512:
        case SignatureScheme.rsa_pss_rsae_sha256:
        case SignatureScheme.rsa_pss_rsae_sha384:
        case SignatureScheme.rsa_pss_rsae_sha512:
            return true;

        case SignatureScheme.ed25519:
        case SignatureScheme.ed448:
        default:
            return false;
        }
    }

    static void removeNonFipsCipherSuites(Collection<String> cipherSuites)
    {
        cipherSuites.retainAll(FIPS_SUPPORTED_CIPHERSUITES);
    }

    static void removeNonFipsProtocols(Collection<String> protocols)
    {
        protocols.retainAll(FIPS_SUPPORTED_PROTOCOLS);
    }
}
