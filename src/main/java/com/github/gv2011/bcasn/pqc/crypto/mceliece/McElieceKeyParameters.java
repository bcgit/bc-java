package com.github.gv2011.bcasn.pqc.crypto.mceliece;

import com.github.gv2011.bcasn.crypto.params.AsymmetricKeyParameter;


public class McElieceKeyParameters
    extends AsymmetricKeyParameter
{
    private McElieceParameters params;

    public McElieceKeyParameters(
        boolean isPrivate,
        McElieceParameters params)
    {
        super(isPrivate);
        this.params = params;
    }


    public McElieceParameters getParameters()
    {
        return params;
    }

}
