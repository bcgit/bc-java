package org.bouncycastle.math.ec.endo;

import java.math.BigInteger;

public class GLVTypeBParameters
{
    protected final BigInteger beta, lambda;
    protected final ScalarSplitParameters splitParams;

    /**
     * @deprecated Use constructor taking a {@link ScalarSplitParameters} instead.
     */
    public GLVTypeBParameters(BigInteger beta, BigInteger lambda, BigInteger[] v1, BigInteger[] v2, BigInteger g1,
        BigInteger g2, int bits)
    {
        this.beta = beta;
        this.lambda = lambda;
        this.splitParams = new ScalarSplitParameters(v1, v2, g1, g2, bits);
    }

    public GLVTypeBParameters(BigInteger beta, BigInteger lambda, ScalarSplitParameters splitParams)
    {
        this.beta = beta;
        this.lambda = lambda;
        this.splitParams = splitParams;
    }

    public BigInteger getBeta()
    {
        return beta;
    }

    public BigInteger getLambda()
    {
        return lambda;
    }

    public ScalarSplitParameters getSplitParams()
    {
        return splitParams;
    }

    /**
     * @deprecated Access via {@link #getSplitParams()} instead.
     */
    public BigInteger getV1A()
    {
        return getSplitParams().getV1A();
    }

    /**
     * @deprecated Access via {@link #getSplitParams()} instead.
     */
    public BigInteger getV1B()
    {
        return getSplitParams().getV1B();
    }

    /**
     * @deprecated Access via {@link #getSplitParams()} instead.
     */
    public BigInteger getV2A()
    {
        return getSplitParams().getV2A();
    }

    /**
     * @deprecated Access via {@link #getSplitParams()} instead.
     */
    public BigInteger getV2B()
    {
        return getSplitParams().getV2B();
    }

    /**
     * @deprecated Access via {@link #getSplitParams()} instead.
     */
    public BigInteger getG1()
    {
        return getSplitParams().getG1();
    }

    /**
     * @deprecated Access via {@link #getSplitParams()} instead.
     */
    public BigInteger getG2()
    {
        return getSplitParams().getG2();
    }
    
    /**
     * @deprecated Access via {@link #getSplitParams()} instead.
     */
    public int getBits()
    {
        return getSplitParams().getBits();
    }
}
