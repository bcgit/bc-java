package org.bouncycastle.jsse.provider;

import java.util.Set;

import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;

abstract class AbstractAlgorithmConstraints implements BCAlgorithmConstraints
{
    protected final AlgorithmDecomposer decomposer;

    AbstractAlgorithmConstraints(AlgorithmDecomposer decomposer)
    {
        this.decomposer = decomposer;
    }

    protected boolean containsAnyPartIgnoreCase(Set<String> elements, String algorithm)
    {
        if (containsIgnoreCase(elements, algorithm))
        {
            return true;
        }

        for (String part : decomposer.decompose(algorithm))
        {
            if (containsIgnoreCase(elements, part))
            {
                return true;
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
}
