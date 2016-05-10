package com.github.gv2011.bcasn.pqc.crypto.gmss;

import com.github.gv2011.bcasn.crypto.params.AsymmetricKeyParameter;

public class GMSSKeyParameters
    extends AsymmetricKeyParameter
{
    private GMSSParameters params;

    public GMSSKeyParameters(
        boolean isPrivate,
        GMSSParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public GMSSParameters getParameters()
    {
        return params;
    }
}