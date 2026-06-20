package org.bouncycastle.crypto.params;

public class FrodoKEMKeyParameters
    extends AsymmetricKeyParameter
{
    private final FrodoKEMParameters params;

    public FrodoKEMKeyParameters(
        boolean isPrivate,
        FrodoKEMParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public FrodoKEMParameters getParameters()
    {
        return params;
    }
}
