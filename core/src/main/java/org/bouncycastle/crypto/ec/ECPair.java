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

    public byte[] getEncoded()
    {
        byte[] xEnc = x.getEncoded();
        byte[] yEnc = y.getEncoded();

        byte[] full = new byte[xEnc.length + yEnc.length];

        System.arraycopy(xEnc, 0, full, 0, xEnc.length);
        System.arraycopy(yEnc, 0, full, xEnc.length, yEnc.length);

        return full;
    }
}
