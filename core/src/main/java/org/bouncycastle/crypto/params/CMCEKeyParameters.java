package org.bouncycastle.crypto.params;

/**
 * @deprecated Now believed unsafe to use - will be removed in a future release.
 */
@Deprecated
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
