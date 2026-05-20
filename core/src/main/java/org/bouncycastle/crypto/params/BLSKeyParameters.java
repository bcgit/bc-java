package org.bouncycastle.crypto.params;

public class BLSKeyParameters
    extends AsymmetricKeyParameter
{
    private final BLSParameters params;

    public BLSKeyParameters(
        boolean isPrivate,
        BLSParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public BLSParameters getParameters()
    {
        return params;
    }
}
