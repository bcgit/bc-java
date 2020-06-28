package org.bouncycastle.jsse.provider;

import java.security.Key;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;

abstract class AbstractAlgorithmConstraints implements BCAlgorithmConstraints
{
    protected final AlgorithmDecomposer decomposer;

    AbstractAlgorithmConstraints(AlgorithmDecomposer decomposer)
    {
        this.decomposer = decomposer;
    }

    protected void checkAlgorithmName(String algorithm)
    {
        if (!JsseUtils.isNameSpecified(algorithm))
        {
            throw new IllegalArgumentException("No algorithm name specified");
        }
    }

    protected void checkKey(Key key)
    {
        if (null == key)
        {
            throw new NullPointerException("'key' cannot be null");
        }
    }

    protected void checkPrimitives(Set<BCCryptoPrimitive> primitives)
    {
        if (!isPrimitivesSpecified(primitives))
        {
            throw new IllegalArgumentException("No cryptographic primitive specified");
        }
    }

    protected boolean containsAnyPartIgnoreCase(Set<String> elements, String algorithm)
    {
        if (elements.isEmpty())
        {
            return false;
        }

        if (containsIgnoreCase(elements, algorithm))
        {
            return true;
        }

        if (null != decomposer)
        {
            for (String part : decomposer.decompose(algorithm))
            {
                if (containsIgnoreCase(elements, part))
                {
                    return true;
                }
            }
        }

        return false;
    }

    protected boolean containsIgnoreCase(Set<String> elements, String s)
    {
        for (String element : elements)
        {
            if (element.equalsIgnoreCase(s))
            {
                return true;
            }
        }
        return false;
    }

    protected boolean isPrimitivesSpecified(Set<BCCryptoPrimitive> primitives)
    {
        return null != primitives && !primitives.isEmpty();
    }

    protected static Set<String> asUnmodifiableSet(String[] algorithms)
    {
        if (null != algorithms && algorithms.length > 0)
        {
            Set<String> result = asSet(algorithms);
            if (!result.isEmpty())
            {
                return Collections.unmodifiableSet(result);
            }
        }
        return Collections.<String> emptySet();
    }

    protected static Set<String> asSet(String[] algorithms)
    {
        Set<String> result = new HashSet<String>();
        if (null != algorithms)
        {
            for (String algorithm : algorithms)
            {
                if (null != algorithm)
                {
                    // TODO[jsse] toLowerCase?
                    result.add(algorithm);
                }
            }
        }
        return result;
    }
}
