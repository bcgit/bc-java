package org.bouncycastle.crypto.params;

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
