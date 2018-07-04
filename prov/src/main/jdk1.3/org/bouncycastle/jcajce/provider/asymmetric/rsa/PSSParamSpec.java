package org.bouncycastle.jcajce.provider.asymmetric.rsa;


import java.security.spec.AlgorithmParameterSpec;

class PSSParamSpec
    implements AlgorithmParameterSpec
{
    private final String digName;
    private final int saltLength;
    
    public PSSParamSpec(int saltLength, String digName)
    {
        this.saltLength = saltLength;
        this.digName = digName;
    }

    public int getSaltLength()
    {
        return saltLength;
    }

    public String getDigestName()
    {
        return digName;
    }
}