package org.bouncycastle.pqc.crypto.slhdsa;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class SLHDSAKeyParameters
    extends AsymmetricKeyParameter
{
    private final SLHDSAParameters parameters;

    protected SLHDSAKeyParameters(boolean isPrivate, SLHDSAParameters parameters)
    {
        super(isPrivate);
        this.parameters = parameters;
    }

    public SLHDSAParameters getParameters()
    {
        return parameters;
    }
}
