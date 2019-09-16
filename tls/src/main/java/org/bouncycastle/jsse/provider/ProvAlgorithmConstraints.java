package org.bouncycastle.jsse.provider;

import java.security.AlgorithmParameters;
import java.security.Key;
import java.util.Set;

import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;

public class ProvAlgorithmConstraints
    implements BCAlgorithmConstraints
{
    private static final String PROPERTY_DISABLED_ALGORITHMS = "jdk.tls.disabledAlgorithms";

    private static final DisabledAlgorithmConstraints provTlsDisabledAlgorithms =
        DisabledAlgorithmConstraints.create(ProvAlgorithmDecomposer.INSTANCE, PROPERTY_DISABLED_ALGORITHMS);

    static final ProvAlgorithmConstraints DEFAULT = new ProvAlgorithmConstraints();

    public ProvAlgorithmConstraints()
    {
        // TODO[jsse]
    }

    public boolean permits(Set<BCCryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters)
    {
        if (null != provTlsDisabledAlgorithms && !provTlsDisabledAlgorithms.permits(primitives, algorithm, parameters))
        {
            return false;
        }

        // TODO[jsse]
        return true;
    }

    public boolean permits(Set<BCCryptoPrimitive> primitives, Key key)
    {
        if (null != provTlsDisabledAlgorithms && !provTlsDisabledAlgorithms.permits(primitives, key))
        {
            return false;
        }

        // TODO[jsse]
        return true;
    }

    public boolean permits(Set<BCCryptoPrimitive> primitives, String algorithm, Key key, AlgorithmParameters parameters)
    {
        if (null != provTlsDisabledAlgorithms && !provTlsDisabledAlgorithms.permits(primitives, algorithm, key, parameters))
        {
            return false;
        }

        // TODO[jsse]
        return true;
    }
}
