package org.bouncycastle.jsse.provider;

import java.security.AlgorithmParameters;
import java.security.Key;
import java.util.Set;

import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;

public class ProvAlgorithmConstraints
    implements BCAlgorithmConstraints
{
    static final ProvAlgorithmConstraints DEFAULT = new ProvAlgorithmConstraints();

    public ProvAlgorithmConstraints()
    {
        // TODO[jsse]
    }

    public boolean permits(Set<BCCryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters)
    {
        // TODO[jsse]
        return true;
    }

    public boolean permits(Set<BCCryptoPrimitive> primitives, Key key)
    {
        // TODO[jsse]
        return true;
    }

    public boolean permits(Set<BCCryptoPrimitive> primitives, String algorithm, Key key, AlgorithmParameters parameters)
    {
        // TODO[jsse]
        return true;
    }
}
