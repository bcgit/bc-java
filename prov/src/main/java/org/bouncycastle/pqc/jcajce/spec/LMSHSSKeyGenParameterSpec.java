package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

/**
 * ParameterSpec for keys using the LMS Hierarchical Signature System (HSS).
 */
public class LMSHSSKeyGenParameterSpec
    implements AlgorithmParameterSpec
{
    private final LMSKeyGenParameterSpec[] specs;

    /**
     * Base constructor, specify the LMS parameters at each level of the hierarchy.
     *
     * @param specs the LMS parameter specs for each level of the hierarchy.
     */
    public LMSHSSKeyGenParameterSpec(LMSKeyGenParameterSpec[] specs)
    {
        this.specs = specs.clone();
    }

    /**
     * Return the LMS parameters for the HSS hierarchy.
     *
     * @return the HSS component LMS parameter specs.
     */
    public LMSKeyGenParameterSpec[] getLMSSpecs()
    {
        return specs.clone();
    }
}
