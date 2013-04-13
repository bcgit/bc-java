package org.bouncycastle.crypto.ec;

import org.bouncycastle.math.ec.ECPoint;

public class ECPair
{
    private ECPoint a;
    private ECPoint b;

    public ECPair(ECPoint a, ECPoint b)
    {
        this.a = a;
        this.b = b;
    }

    public ECPoint getA()
    {
        return a;
    }

    public ECPoint getB()
    {
        return b;
    }
}
