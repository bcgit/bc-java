package com.github.gv2011.bcasn.math.ec.endo;

import java.math.BigInteger;

public class GLVTypeBParameters
{
    private static void checkVector(BigInteger[] v, String name)
    {
        if (v == null || v.length != 2 || v[0] == null || v[1] == null)
        {
            throw new IllegalArgumentException("'" + name + "' must consist of exactly 2 (non-null) values");
        }
    }

    protected final BigInteger beta;
    protected final BigInteger lambda;
    protected final BigInteger v1A, v1B, v2A, v2B;
    protected final BigInteger g1, g2;
    protected final int bits;

    public GLVTypeBParameters(BigInteger beta, BigInteger lambda, BigInteger[] v1, BigInteger[] v2, BigInteger g1,
        BigInteger g2, int bits)
    {
        checkVector(v1, "v1");
        checkVector(v2, "v2");

        this.beta = beta;
        this.lambda = lambda;
        this.v1A = v1[0];
        this.v1B = v1[1];
        this.v2A = v2[0];
        this.v2B = v2[1];
        this.g1 = g1;
        this.g2 = g2;
        this.bits = bits;
    }

    public BigInteger getBeta()
    {
        return beta;
    }

    public BigInteger getLambda()
    {
        return lambda;
    }

    /**
     * @deprecated Use {@link #getV1A()} and {@link #getV1B()} instead.
     */
    public BigInteger[] getV1()
    {
        return new BigInteger[]{ v1A, v1B };
    }

    public BigInteger getV1A()
    {
        return v1A;
    }

    public BigInteger getV1B()
    {
        return v1B;
    }

    /**
     * @deprecated Use {@link #getV2A()} and {@link #getV2B()} instead.
     */
    public BigInteger[] getV2()
    {
        return new BigInteger[]{ v2A, v2B };
    }

    public BigInteger getV2A()
    {
        return v2A;
    }

    public BigInteger getV2B()
    {
        return v2B;
    }

    public BigInteger getG1()
    {
        return g1;
    }

    public BigInteger getG2()
    {
        return g2;
    }
    
    public int getBits()
    {
        return bits;
    }
}
