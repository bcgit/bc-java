package org.bouncycastle.jsse.provider;

import java.security.AlgorithmParameters;
import java.security.Key;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;

class DisabledAlgorithmConstraints
    extends AbstractAlgorithmConstraints
{
    static DisabledAlgorithmConstraints create(AlgorithmDecomposer decomposer, String propertyName)
    {
        String[] algorithms = PropertyUtils.getStringArraySystemProperty(propertyName);
        if (null == algorithms)
        {
            return null;
        }

        Set<String> result = new HashSet<String>();
        for (String algorithm : algorithms)
        {
            // TODO[jsse] toLowerCase?
            result.add(algorithm);
        }

        return new DisabledAlgorithmConstraints(decomposer, result);
    }

    private final Set<String> disabledAlgorithms;

    private DisabledAlgorithmConstraints(AlgorithmDecomposer decomposer, Set<String> disabledAlgorithms)
    {
        super(decomposer);

        this.disabledAlgorithms = disabledAlgorithms; 
    }

    public final boolean permits(Set<BCCryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters)
    {
        checkAlgorithmName(algorithm);

        if (containsAnyPartIgnoreCase(disabledAlgorithms, algorithm))
        {
            return false;
        }

        if (null == parameters)
        {
            return true;
        }

        // TODO[jsse] Check whether the constraints permit these parameters for the given algorithm
        return true;
    }

    public final boolean permits(Set<BCCryptoPrimitive> primitives, Key key)
    {
        return checkConstraints(primitives, "", key, null);
    }

    public final boolean permits(Set<BCCryptoPrimitive> primitives, String algorithm, Key key, AlgorithmParameters parameters)
    {
        checkAlgorithmName(algorithm);

        return checkConstraints(primitives, algorithm, key, parameters);
    }

    private void checkAlgorithmName(String algorithm)
    {
        if (!isAlgorithmSpecified(algorithm))
        {
            throw new IllegalArgumentException("No algorithm name specified");
        }
    }

    private boolean checkConstraints(Set<BCCryptoPrimitive> primitives, String algorithm, Key key,
        AlgorithmParameters parameters)
    {
        checkKey(key);

        if (isAlgorithmSpecified(algorithm)
            && !permits(primitives, algorithm, parameters))
        {
            return false;
        }

        if (!permits(primitives, key.getAlgorithm(), null))
        {
            return false;
        }

        // TODO[jsse] Check whether key size constraints permit the given key
        return true;
    }

    private void checkKey(Key key)
    {
        if (null == key)
        {
            throw new NullPointerException("'key' cannot be null");
        }
    }

    private boolean isAlgorithmSpecified(String algorithm)
    {
        return null != algorithm && algorithm.length() > 0;
    }
}
