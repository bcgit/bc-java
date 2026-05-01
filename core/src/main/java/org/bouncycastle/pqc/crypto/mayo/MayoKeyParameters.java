package org.bouncycastle.pqc.crypto.mayo;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class MayoKeyParameters
    extends AsymmetricKeyParameter
{
    private final MayoParameters params;

    public MayoKeyParameters(
        boolean isPrivate,
        MayoParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public MayoParameters getParameters()
    {
        return params;
    }
}
