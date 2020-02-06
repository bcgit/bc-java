package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class LMSHSSParameterSpec
    implements AlgorithmParameterSpec
{
    private final LMSParameterSpec[] specs;

    public LMSHSSParameterSpec(LMSParameterSpec[] specs)
    {
        this.specs = specs.clone();
    }

    public LMSParameterSpec[] getLMSSpecs()
    {
        return specs.clone();
    }
}
