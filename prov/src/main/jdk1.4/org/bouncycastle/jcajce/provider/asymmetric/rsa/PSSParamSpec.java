package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.security.spec.PSSParameterSpec;

public class PSSParamSpec
    extends PSSParameterSpec
{
    private final String digName;

    public PSSParamSpec(int saltLength, String digName)
    {
        super(saltLength);
        this.digName = digName;
    }

    public String getDigestName()
    {
        return digName;
    }
}