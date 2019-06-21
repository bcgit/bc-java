package org.bouncycastle.math.ec.endo;

import java.math.BigInteger;

public class GLVTypeAParameters
{
    protected final BigInteger i, lambda;
    protected final ScalarSplitParameters splitParams;

    public GLVTypeAParameters(BigInteger i, BigInteger lambda, ScalarSplitParameters splitParams)
    {
        this.i = i;
        this.lambda = lambda;
        this.splitParams = splitParams;
    }

    public BigInteger getI()
    {
        return i;
    }

    public BigInteger getLambda()
    {
        return lambda;
    }

    public ScalarSplitParameters getSplitParams()
    {
        return splitParams;
    }
}
