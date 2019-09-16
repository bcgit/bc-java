package org.bouncycastle.jsse.provider;

import java.util.HashSet;
import java.util.Set;

class ProvAlgorithmDecomposer
    implements AlgorithmDecomposer
{
    static final ProvAlgorithmDecomposer INSTANCE = new ProvAlgorithmDecomposer();

    private ProvAlgorithmDecomposer() {}

    public Set<String> decompose(String algorithm)
    {
        if (null == algorithm || algorithm.length() < 1)
        {
            throw new IllegalArgumentException();
        }

        // TODO[jsse]
        Set<String> result = new HashSet<String>(1);
        result.add(algorithm);
        return result;
    }
}
