package org.bouncycastle.jsse.provider;

import java.security.AlgorithmParameters;
import java.security.Key;
import java.util.Set;

import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;

class ProvAlgorithmConstraints
    extends AbstractAlgorithmConstraints
{
    /*
     * NOTE: In case these security properties are absent, we supply defaults drawn from recent
     * JDKs. This is an incompatibility with SunJSSE (which treats these absent properties as simply
     * an empty list), justified by the fact that we may be running on old or non-standard JVMs.
     */
    private static final String PROPERTY_CERTPATH_DISABLED_ALGORITHMS = "jdk.certpath.disabledAlgorithms";
    private static final String PROPERTY_TLS_DISABLED_ALGORITHMS = "jdk.tls.disabledAlgorithms";

    private static final String DEFAULT_CERTPATH_DISABLED_ALGORITHMS =
        "MD2, MD5, SHA1 jdkCA & usage TLSServer, RSA keySize < 1024, DSA keySize < 1024, EC keySize < 224, " +
        "include jdk.disabled.namedCurves";
    private static final String DEFAULT_TLS_DISABLED_ALGORITHMS =
        "SSLv3, RC4, DES, MD5withRSA, DH keySize < 1024, EC keySize < 224, 3DES_EDE_CBC, anon, NULL, " +
        "include jdk.disabled.namedCurves";

    private static final DisabledAlgorithmConstraints provTlsDisabledAlgorithms = DisabledAlgorithmConstraints.create(
        ProvAlgorithmDecomposer.INSTANCE_TLS, PROPERTY_TLS_DISABLED_ALGORITHMS, DEFAULT_TLS_DISABLED_ALGORITHMS);
    private static final DisabledAlgorithmConstraints provX509DisabledAlgorithms = DisabledAlgorithmConstraints.create(
        ProvAlgorithmDecomposer.INSTANCE_X509, PROPERTY_CERTPATH_DISABLED_ALGORITHMS,
        DEFAULT_CERTPATH_DISABLED_ALGORITHMS);

    static final ProvAlgorithmConstraints DEFAULT = new ProvAlgorithmConstraints(null, true);
    static final ProvAlgorithmConstraints DEFAULT_TLS_ONLY = new ProvAlgorithmConstraints(null, false);

    private final BCAlgorithmConstraints configAlgorithmConstraints;
    private final Set<String> supportedSignatureAlgorithms;
    private final boolean enableX509Constraints;

    ProvAlgorithmConstraints(BCAlgorithmConstraints configAlgorithmConstraints, boolean enableX509Constraints)
    {
        super(null);

        this.configAlgorithmConstraints = configAlgorithmConstraints;
        this.supportedSignatureAlgorithms = null;
        this.enableX509Constraints = enableX509Constraints;
    }

    ProvAlgorithmConstraints(BCAlgorithmConstraints configAlgorithmConstraints,
        String[] supportedSignatureAlgorithms, boolean enableX509Constraints)
    {
        super(null);

        this.configAlgorithmConstraints = configAlgorithmConstraints;
        this.supportedSignatureAlgorithms = asUnmodifiableSet(supportedSignatureAlgorithms);
        this.enableX509Constraints = enableX509Constraints;
    }

    public boolean permits(Set<BCCryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters)
    {
        checkPrimitives(primitives);
        checkAlgorithmName(algorithm);

        if (null != supportedSignatureAlgorithms)
        {
            String algorithmBC = algorithm;
            algorithm = getAlgorithm(algorithmBC);

            if (!isSupportedSignatureAlgorithm(algorithmBC))
            {
                return false;
            }
        }

        if (null != configAlgorithmConstraints && !configAlgorithmConstraints.permits(primitives, algorithm, parameters))
        {
            return false;
        }

        if (null != provTlsDisabledAlgorithms && !provTlsDisabledAlgorithms.permits(primitives, algorithm, parameters))
        {
            return false;
        }

        if (enableX509Constraints && null != provX509DisabledAlgorithms
            && !provX509DisabledAlgorithms.permits(primitives, algorithm, parameters))
        {
            return false;
        }

        return true;
    }

    public boolean permits(Set<BCCryptoPrimitive> primitives, Key key)
    {
        checkPrimitives(primitives);
        checkKey(key);

        if (null != configAlgorithmConstraints && !configAlgorithmConstraints.permits(primitives, key))
        {
            return false;
        }

        if (null != provTlsDisabledAlgorithms && !provTlsDisabledAlgorithms.permits(primitives, key))
        {
            return false;
        }

        if (enableX509Constraints && null != provX509DisabledAlgorithms
            && !provX509DisabledAlgorithms.permits(primitives, key))
        {
            return false;
        }

        return true;
    }

    public boolean permits(Set<BCCryptoPrimitive> primitives, String algorithm, Key key, AlgorithmParameters parameters)
    {
        checkPrimitives(primitives);
        checkAlgorithmName(algorithm);
        checkKey(key);

        if (null != supportedSignatureAlgorithms)
        {
            String algorithmBC = algorithm;
            algorithm = getAlgorithm(algorithmBC);

            if (!isSupportedSignatureAlgorithm(algorithmBC))
            {
                return false;
            }
        }

        if (null != configAlgorithmConstraints && !configAlgorithmConstraints.permits(primitives, algorithm, key, parameters))
        {
            return false;
        }

        if (null != provTlsDisabledAlgorithms && !provTlsDisabledAlgorithms.permits(primitives, algorithm, key, parameters))
        {
            return false;
        }

        if (enableX509Constraints && null != provX509DisabledAlgorithms
            && !provX509DisabledAlgorithms.permits(primitives, algorithm, key, parameters))
        {
            return false;
        }

        return true;
    }

    private String getAlgorithm(String algorithmBC)
    {
        int colonPos = algorithmBC.indexOf(':');
        return colonPos < 0 ? algorithmBC : algorithmBC.substring(0, colonPos);
    }

    private boolean isSupportedSignatureAlgorithm(String algorithmBC)
    {
        return containsIgnoreCase(supportedSignatureAlgorithms, algorithmBC);
    }
}
