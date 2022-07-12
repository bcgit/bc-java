package org.bouncycastle.pqc.math.ntru;

import org.bouncycastle.pqc.math.ntru.parameters.NTRUHPSParameterSet;

/**
 * Polynomial class for HPS parameters with q = 4096
 */
public class HPS4096Polynomial
    extends HPSPolynomial
{
    public HPS4096Polynomial(NTRUHPSParameterSet params)
    {
        super(params);
    }

    @Override
    public byte[] sqToBytes(int len)
    {
        byte[] r = new byte[len];
        int q = params.q();
        int i;

        for (i = 0; i < params.packDegree() / 2; i++)
        {
            r[3 * i + 0] = (byte)(modQ((this.coeffs[2 * i + 0] & 0xffff), q) & 0xff);
            r[3 * i + 1] = (byte)((modQ((this.coeffs[2 * i + 0] & 0xffff), q) >>> 8) | ((modQ((this.coeffs[2 * i + 1] & 0xffff), q) & 0x0f) << 4));
            r[3 * i + 2] = (byte)((modQ((this.coeffs[2 * i + 1] & 0xffff), q) >>> 4));
        }

        return r;
    }

    @Override
    public void sqFromBytes(byte[] a)
    {
        int i;
        for (i = 0; i < params.packDegree() / 2; i++)
        {
            this.coeffs[2 * i + 0] = (short)(((a[3 * i + 0] & 0xff) >>> 0) | (((short)(a[3 * i + 1] & 0xff) & 0x0f) << 8));
            this.coeffs[2 * i + 1] = (short)(((a[3 * i + 1] & 0xff) >>> 4) | (((short)(a[3 * i + 2] & 0xff) & 0xff) << 4));
        }
        this.coeffs[params.n() - 1] = 0;
    }
}
