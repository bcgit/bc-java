package org.bouncycastle.pqc.crypto.mirath;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class MirathKeyParameters
    extends AsymmetricKeyParameter
{
    private final MirathParameters params;

    public MirathKeyParameters(
        boolean isPrivate,
        MirathParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public MirathParameters getParameters()
    {
        return params;
    }
}