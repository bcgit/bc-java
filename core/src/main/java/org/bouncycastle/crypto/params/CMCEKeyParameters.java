package org.bouncycastle.crypto.params;

public class CMCEKeyParameters
    extends AsymmetricKeyParameter
{
    private final CMCEParameters params;

    public CMCEKeyParameters(
        boolean isPrivate,
        CMCEParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public CMCEParameters getParameters()
    {
        return params;
    }
}
