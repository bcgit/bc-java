package org.bouncycastle.pqc.crypto.ntruplus;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class NTRUPlusKeyParameters
    extends AsymmetricKeyParameter
{
    private final NTRUPlusParameters params;

    public NTRUPlusKeyParameters(
        boolean isPrivate,
        NTRUPlusParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public NTRUPlusParameters getParameters()
    {
        return params;
    }
}

