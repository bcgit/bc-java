package com.github.gv2011.bcasn.pqc.crypto.mceliece;

import com.github.gv2011.bcasn.crypto.params.AsymmetricKeyParameter;


public class McElieceCCA2KeyParameters
    extends AsymmetricKeyParameter
{
    private McElieceCCA2Parameters params;

    public McElieceCCA2KeyParameters(
        boolean isPrivate,
        McElieceCCA2Parameters params)
    {
        super(isPrivate);
        this.params = params;
    }


    public McElieceCCA2Parameters getParameters()
    {
        return params;
    }

}
