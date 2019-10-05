package org.bouncycastle.jsse.provider;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.tls.NamedGroup;

abstract class FipsUtils
{
    private static final boolean provAllowRSAKeyExchange = PropertyUtils.getBooleanSystemProperty("org.bouncycastle.jsse.fips.allowRSAKeyExchange", true);
    // This can only be set to true if the underlying provider is able to assert it is compliant with FIPS IG A.5
    // and a mechanism has been integrated into this API accordingly to ensure that is the case.
    private static final boolean canSupportGCM = false;

    private static final Set<String> FIPS_SUPPORTED_CIPHERSUITES = createFipsSupportedCipherSuites();
    private static final Set<String> FIPS_SUPPORTED_PROTOCOLS = createFipsSupportedProtocols();

    private static Set<String> createFipsSupportedCipherSuites()
    {
        final Set<String> cs = new HashSet<String>();

        // "shall support"

        // "shall support" (TLS 1.2)

        // "should support"
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
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
        if (canSupportGCM)
        {
            cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
            cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
        }
        cs.add("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");
        if (canSupportGCM)
        {
            cs.add("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        }

        // "may support" (TLS 1.2);
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
        cs.add("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256");
        if (canSupportGCM)
        {
            cs.add("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256");
            cs.add("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384");
        }
        cs.add("TLS_DH_DSS_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_DH_DSS_WITH_AES_256_CBC_SHA256");
        if (canSupportGCM)
        {
            cs.add("TLS_DH_DSS_WITH_AES_128_GCM_SHA256");
            cs.add("TLS_DH_DSS_WITH_AES_256_GCM_SHA384");
        }
        cs.add("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384");
        if (canSupportGCM)
        {
            cs.add("TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256");
            cs.add("TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384");
        }

        if (provAllowRSAKeyExchange)
        {
            // "shall support"
            cs.add("TLS_RSA_WITH_3DES_EDE_CBC_SHA");
            cs.add("TLS_RSA_WITH_AES_128_CBC_SHA");

            // "shall support" (TLS 1.2)
            if (canSupportGCM)
            {
                cs.add("TLS_RSA_WITH_AES_128_GCM_SHA256");
            }

            // "should support"
            cs.add("TLS_RSA_WITH_AES_256_CBC_SHA");

            // "may support"

            // "should support" (TLS 1.2)
            if (canSupportGCM)
            {
                cs.add("TLS_RSA_WITH_AES_256_GCM_SHA384");
            }

            // "may support" (TLS 1.2);
            cs.add("TLS_RSA_WITH_AES_128_CBC_SHA256");
            cs.add("TLS_RSA_WITH_AES_256_CBC_SHA256");
            cs.add("TLS_RSA_WITH_AES_128_CCM");
            cs.add("TLS_RSA_WITH_AES_256_CCM");
        }

        return Collections.unmodifiableSet(cs);
    }

    private static Set<String> createFipsSupportedProtocols()
    {
        final Set<String> ps = new HashSet<String>();

        ps.add("TLSv1");
        ps.add("TLSv1.1");
        ps.add("TLSv1.2");

        return Collections.unmodifiableSet(ps);
    }

    static int getFipsDefaultDH(int minimumFiniteFieldBits)
    {
        return minimumFiniteFieldBits <= 2048 ? NamedGroup.ffdhe2048
            :  minimumFiniteFieldBits <= 3072 ? NamedGroup.ffdhe3072
            :  minimumFiniteFieldBits <= 4096 ? NamedGroup.ffdhe4096
            :  minimumFiniteFieldBits <= 6144 ? NamedGroup.ffdhe6144
            :  minimumFiniteFieldBits <= 8192 ? NamedGroup.ffdhe8192
            :  -1;
    }

    static int getFipsDefaultECDH(int minimumCurveBits)
    {
        return minimumCurveBits <= 256 ? NamedGroup.secp256r1
            :  minimumCurveBits <= 384 ? NamedGroup.secp384r1
            :  -1;
    }

    static int getFipsMaximumCurveBits()
    {
        return 384;
    }

    static int getFipsMaximumFiniteFieldBits()
    {
        return 8192;
    }

    static boolean isFipsCipherSuite(String cipherSuite)
    {
        return cipherSuite != null && FIPS_SUPPORTED_CIPHERSUITES.contains(cipherSuite);
    }

    static boolean isFipsProtocol(String protocol)
    {
        return protocol != null && FIPS_SUPPORTED_PROTOCOLS.contains(protocol);
    }

    static boolean isFipsNamedGroup(int namedGroup)
    {
        switch (namedGroup)
        {
        case NamedGroup.secp256r1:
        case NamedGroup.secp384r1:
        case NamedGroup.ffdhe2048:
        case NamedGroup.ffdhe3072:
        case NamedGroup.ffdhe4096:
        case NamedGroup.ffdhe6144:
        case NamedGroup.ffdhe8192:
            return true;

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
