package org.bouncycastle.jsse.provider.test;

import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

abstract class FipsTestUtils
{
    /**
     * In FIPS mode, GCM cipher suites (for TLS 1.2) are enabled if and only if the JcaTlsCrypto instance
     * returns a non-null value from getFipsGCMNonceGeneratorFactory. This flag allows to enable/disable that
     * support for the FIPS tests in this package.
     */
    static final boolean enableGCMCiphersIn12 = true;

    static final boolean provAllowRSAKeyExchange =
        "true".equalsIgnoreCase(System.getProperty("org.bouncycastle.jsse.fips.allowRSAKeyExchange"));

    private static final Set<String> FIPS_CIPHERSUITES = createFipsCipherSuites(enableGCMCiphersIn12);

    private static Set<String> createFipsCipherSuites(boolean includeGCM12)
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
        cs.add("TLS_AES_128_GCM_SHA256");
        cs.add("TLS_AES_256_GCM_SHA384");

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

        if (includeGCM12)
        {
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

        if (FipsTestUtils.provAllowRSAKeyExchange)
        {
            cs.add("TLS_RSA_WITH_AES_128_CBC_SHA");
            cs.add("TLS_RSA_WITH_AES_128_CBC_SHA256");
            cs.add("TLS_RSA_WITH_AES_128_CCM");
            cs.add("TLS_RSA_WITH_AES_128_CCM_8");
            cs.add("TLS_RSA_WITH_AES_256_CBC_SHA");
            cs.add("TLS_RSA_WITH_AES_256_CBC_SHA256");
            cs.add("TLS_RSA_WITH_AES_256_CCM");
            cs.add("TLS_RSA_WITH_AES_256_CCM_8");

            if (includeGCM12)
            {
                cs.add("TLS_RSA_WITH_AES_128_GCM_SHA256");
                cs.add("TLS_RSA_WITH_AES_256_GCM_SHA384");
            }
        }

        return Collections.unmodifiableSet(cs);
    }

    static boolean isFipsCipherSuite(String cipherSuite)
    {
        return FIPS_CIPHERSUITES.contains(cipherSuite);
    }

    static void setupFipsSuite()
    {
        if (!enableGCMCiphersIn12)
        {
            ProviderUtils.setupHighPriority(true);
            return;
        }

        Provider bc = ProviderUtils.getProviderBC();

        if (bc == null)
        {
            bc = ProviderUtils.createProviderBC();
        }
        else
        {
            ProviderUtils.removeProviderBC();
        }

        ProviderUtils.removeProviderBCJSSE();

        Provider bcjsse = ProviderUtils.createProviderBCJSSE(true, new FipsJcaTlsCryptoProvider().setProvider(bc));

        Security.insertProviderAt(bc, 1);
        Security.insertProviderAt(bcjsse, 2);
    }

    static void teardownFipsSuite()
    {
        if (enableGCMCiphersIn12)
        {
            ProviderUtils.removeProviderBCJSSE();
        }
    }
}
