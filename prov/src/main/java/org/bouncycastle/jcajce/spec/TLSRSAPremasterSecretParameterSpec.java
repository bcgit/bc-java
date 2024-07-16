package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class TLSRSAPremasterSecretParameterSpec
    implements AlgorithmParameterSpec
{
    private final int protocolVersion;

    public TLSRSAPremasterSecretParameterSpec(int protocolVersion)
    {
         this.protocolVersion = protocolVersion;
    }

    public int getProtocolVersion()
    {
        return protocolVersion;
    }
}
