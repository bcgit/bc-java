package org.bouncycastle.crypto.params;

public class MLDSAKeyParameters
    extends AsymmetricKeyParameter
{
    private final MLDSAParameters params;

    public MLDSAKeyParameters(
        boolean isPrivate,
        MLDSAParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public MLDSAParameters getParameters()
    {
        return params;
    }
}
