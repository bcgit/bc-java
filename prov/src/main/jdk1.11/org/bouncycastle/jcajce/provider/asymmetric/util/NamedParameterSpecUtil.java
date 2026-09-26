package org.bouncycastle.jcajce.provider.asymmetric.util;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;

/**
 * Version hook producing the JDK form of a key's named parameter set, as returned by the
 * getParams() method keys inherit from java.security.AsymmetricKey from Java 22.
 * <p>
 * This is the Java 11 copy, returning a NamedParameterSpec. The base copy returns null - keep
 * the method set of the two copies identical, and put nothing else on this class.
 * </p>
 */
public class NamedParameterSpecUtil
{
    /**
     * Return a NamedParameterSpec for the passed in parameter set name.
     *
     * @param name the standard name of the parameter set, for example "ML-DSA-65".
     * @return a NamedParameterSpec carrying name.
     */
    public static AlgorithmParameterSpec getNamedParameterSpec(String name)
    {
        return new NamedParameterSpec(name);
    }
}
