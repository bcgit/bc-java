package org.bouncycastle.crypto.ec;

import org.bouncycastle.math.ec.ECPoint;

public class ECPair
{
    private final ECPoint x;
    private final ECPoint y;

    public ECPair(ECPoint x, ECPoint y)
    {
        this.x = x;
        this.y = y;
    }

    public ECPoint getX()
    {
        return x;
    }

    public ECPoint getY()
    {
        return y;
    }
}
