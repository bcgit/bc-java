package com.github.gv2011.bcasn.asn1.x9;

public abstract class X9ECParametersHolder
{
    private X9ECParameters params;

    public synchronized X9ECParameters getParameters()
    {
        if (params == null)
        {
            params = createParameters();
        }

        return params;
    }

    protected abstract X9ECParameters createParameters();
}
