package org.bouncycastle.jcajce.provider.asymmetric.util;

import java.security.spec.AlgorithmParameterSpec;

/**
 * Version hook producing the JDK form of a key's named parameter set, as returned by the
 * getParams() method keys inherit from java.security.AsymmetricKey from Java 22.
 * <p>
 * java.security.spec.NamedParameterSpec only exists from Java 11, so this copy, loaded on earlier
 * JVMs, has nothing to offer and returns null. The jdk1.11 twin returns a NamedParameterSpec - keep
 * the method set of the two copies identical, and put nothing else on this class.
 * </p>
 */
public class NamedParameterSpecUtil
{
    /**
     * Return a NamedParameterSpec for the passed in parameter set name, if the JVM has one.
     *
     * @param name the standard name of the parameter set, for example "ML-DSA-65".
     * @return null, as NamedParameterSpec is not available before Java 11.
     */
    public static AlgorithmParameterSpec getNamedParameterSpec(String name)
    {
        return null;
    }
}
