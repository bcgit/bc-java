package org.bouncycastle.pqc.crypto.uov;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class UOVKeyParameters
    extends AsymmetricKeyParameter
{
    private final UOVParameters params;

    public UOVKeyParameters(
        boolean isPrivate,
        UOVParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public UOVParameters getParameters()
    {
        return params;
    }
}
