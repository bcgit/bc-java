package org.bouncycastle.pqc.crypto.cross;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class CrossKeyParameters
    extends AsymmetricKeyParameter
{
    private final CrossParameters params;

    public CrossKeyParameters(
        boolean isPrivate,
        CrossParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public CrossParameters getParameters()
    {
        return params;
    }
}
