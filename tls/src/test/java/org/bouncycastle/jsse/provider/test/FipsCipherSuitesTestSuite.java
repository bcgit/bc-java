package org.bouncycastle.jsse.provider.test;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import junit.framework.Test;
import junit.framework.TestSuite;

public class FipsCipherSuitesTestSuite
    extends TestSuite
{
    private static final boolean provAllowGCMCiphers = false;
    private static final boolean provAllowRSAKeyExchange = true;

    private static final Set<String> FIPS_SUPPORTED_CIPHERSUITES = createFipsSupportedCipherSuites();

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

    static boolean isFipsSupportedCipherSuites(String cipherSuite)
    {
        return FIPS_SUPPORTED_CIPHERSUITES.contains(cipherSuite);
    }

    public FipsCipherSuitesTestSuite()
    {
        super("FIPS CipherSuites");
    }

    public static Test suite()
        throws Exception
    {
        return CipherSuitesTestSuite.createSuite(new FipsCipherSuitesTestSuite(), "FIPS", true, new CipherSuitesFilter()
        {
            public boolean isIgnored(String cipherSuite)
            {
                return false;
            }

            public boolean isPermitted(String cipherSuite)
            {
                return isFipsSupportedCipherSuites(cipherSuite);
            }
        });
    }
}
