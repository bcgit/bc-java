package org.bouncycastle.jsse.provider;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.tls.NamedGroup;

abstract class FipsUtils
{
    private static final Set<String> FIPS_SUPPORTED_CIPHERSUITES = createFipsSupportedCipherSuites();

    private static Set<String> createFipsSupportedCipherSuites()
    {
        final Set<String> cs = new HashSet<String>();

        // "shall support"
        cs.add("TLS_RSA_WITH_3DES_EDE_CBC_SHA");
        cs.add("TLS_RSA_WITH_AES_128_CBC_SHA");

        // "shall support" (TLS 1.2)
//        cs.add("TLS_RSA_WITH_AES_128_GCM_SHA256");

        // "should support"
        cs.add("TLS_RSA_WITH_AES_256_CBC_SHA");
        cs.add("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
        cs.add("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA");
        cs.add("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");

        // "may support"
        cs.add("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");
        cs.add("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA");
        cs.add("TLS_DHE_DSS_WITH_AES_128_CBC_SHA");
        cs.add("TLS_DHE_DSS_WITH_AES_256_CBC_SHA");
        cs.add("TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA");
        cs.add("TLS_DH_DSS_WITH_AES_128_CBC_SHA");
        cs.add("TLS_DH_DSS_WITH_AES_256_CBC_SHA");
        cs.add("TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA");
        cs.add("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA");
        cs.add("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA");

        // "should support" (TLS 1.2)
//        cs.add("TLS_RSA_WITH_AES_256_GCM_SHA384");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
//        cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
//        cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
        cs.add("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");
//        cs.add("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");

        // "may support" (TLS 1.2);
        cs.add("TLS_RSA_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_RSA_WITH_AES_256_CBC_SHA256");
        cs.add("TLS_RSA_WITH_AES_128_CCM");
        cs.add("TLS_RSA_WITH_AES_256_CCM");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
        cs.add("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256");
//        cs.add("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256");
//        cs.add("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384");
        cs.add("TLS_DH_DSS_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_DH_DSS_WITH_AES_256_CBC_SHA256");
//        cs.add("TLS_DH_DSS_WITH_AES_128_GCM_SHA256");
//        cs.add("TLS_DH_DSS_WITH_AES_256_GCM_SHA384");
        cs.add("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384");
//        cs.add("TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256");
//        cs.add("TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384");

        return Collections.unmodifiableSet(cs);
    }

    static int getFipsMaximumCurveBits()
    {
        return 384;
    }

    static boolean isFipsCipherSuite(String cipherSuite)
    {
        return cipherSuite != null && FIPS_SUPPORTED_CIPHERSUITES.contains(cipherSuite);
    }

    static boolean isFipsCurve(int namedGroup)
    {
        switch (namedGroup)
        {
        case NamedGroup.secp256r1:
        case NamedGroup.secp384r1:
            return true;

        default:
            return false;
        }
    }

    static void removeNonFipsCipherSuites(Collection<String> cipherSuites)
    {
        cipherSuites.retainAll(FIPS_SUPPORTED_CIPHERSUITES);
    }
}
