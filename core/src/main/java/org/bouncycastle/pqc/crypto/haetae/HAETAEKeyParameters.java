package org.bouncycastle.pqc.crypto.haetae;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class HAETAEKeyParameters
    extends AsymmetricKeyParameter
{
    private final HAETAEParameters params;

    public HAETAEKeyParameters(
        boolean isPrivate,
        HAETAEParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public HAETAEParameters getParameters()
    {
        return params;
    }
}
