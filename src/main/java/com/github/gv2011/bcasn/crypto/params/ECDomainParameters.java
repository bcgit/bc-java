package com.github.gv2011.bcasn.crypto.params;

import java.math.BigInteger;

import com.github.gv2011.bcasn.math.ec.ECConstants;
import com.github.gv2011.bcasn.math.ec.ECCurve;
import com.github.gv2011.bcasn.math.ec.ECPoint;
import com.github.gv2011.bcasn.util.Arrays;

public class ECDomainParameters
    implements ECConstants
{
    private ECCurve     curve;
    private byte[]      seed;
    private ECPoint     G;
    private BigInteger  n;
    private BigInteger  h;

    public ECDomainParameters(
        ECCurve     curve,
        ECPoint     G,
        BigInteger  n)
    {
        this(curve, G, n, ONE, null);
    }

    public ECDomainParameters(
        ECCurve     curve,
        ECPoint     G,
        BigInteger  n,
        BigInteger  h)
    {
        this(curve, G, n, h, null);
    }

    public ECDomainParameters(
        ECCurve     curve,
        ECPoint     G,
        BigInteger  n,
        BigInteger  h,
        byte[]      seed)
    {
        this.curve = curve;
        this.G = G.normalize();
        this.n = n;
        this.h = h;
        this.seed = seed;
    }

    public ECCurve getCurve()
    {
        return curve;
    }

    public ECPoint getG()
    {
        return G;
    }

    public BigInteger getN()
    {
        return n;
    }

    public BigInteger getH()
    {
        return h;
    }

    public byte[] getSeed()
    {
        return Arrays.clone(seed);
    }
}
