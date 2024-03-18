package org.bouncycastle.pqc.math.ntru;

import org.bouncycastle.pqc.math.ntru.parameters.NTRUHRSSParameterSet;

public class HRSS1373Polynomial
    extends HRSSPolynomial
{
    private static final int L = ((1373 + 31) / 32) * 32;
    private static final int M = L / 4;
    private static final int K = L / 16;

    public HRSS1373Polynomial(NTRUHRSSParameterSet params)
    {
        super(params);
    }

    @Override
    public byte[] sqToBytes(int len)
    {
        byte[] r = new byte[len];
        int i, j;
        short[] t = new short[4];

        for (i = 0; i < params.packDegree() / 4; i++)
        {
            for (j = 0; j < 4; j++)
            {
                t[j] = (short)modQ(this.coeffs[4 * i + j] & 0xffff, params.q());
            }

            //     t0   t1  t2  t3
            //  r0  8
            //  r1  6 | 2
            //  r2      8
            //  r3      4 | 4
            //  r4          8
            //  r5          2 | 6
            //  r6              8

            r[7 * i + 0] = (byte)(t[0] & 0xff);
            r[7 * i + 1] = (byte)((t[0] >>> 8) | ((t[1] & 0x03) << 6));
            r[7 * i + 2] = (byte)((t[1] >>> 2) & 0xff);
            r[7 * i + 3] = (byte)((t[1] >>> 10) | ((t[2] & 0x0f) << 4));
            r[7 * i + 4] = (byte)((t[2] >>> 4) & 0xff);
            r[7 * i + 5] = (byte)((t[2] >>> 12) | ((t[3] & 0x3f) << 2));
            r[7 * i + 6] = (byte)(t[3] >>> 6);
        }

        // i=NTRU_PACK_DEG/4;
        if (params.packDegree() % 4 == 2)
        {
            t[0] = (short)modQ(this.coeffs[params.packDegree() - 2] & 0xffff, params.q());
            t[1] = (short)modQ(this.coeffs[params.packDegree() - 1] & 0xffff, params.q());
            r[7 * i + 0] = (byte)(t[0] & 0xff);
            r[7 * i + 1] = (byte)((t[0] >>> 8) | ((t[1] & 0x03) << 6));
            r[7 * i + 2] = (byte)((t[1] >>> 2) & 0xff);
            r[7 * i + 3] = (byte)(t[1] >>> 10);
        }

        return r;
    }

    @Override
    public void sqFromBytes(byte[] a)
    {
        int i;
        for (i = 0; i < params.packDegree() / 4; i++)
        {
            this.coeffs[4 * i + 0] = (short)((a[7 * i + 0] & 0xff) | (((short)(a[7 * i + 1] & 0xff) & 0x3f) << 8));
            this.coeffs[4 * i + 1] = (short)(((a[7 * i + 1] & 0xff) >>> 6) | (((short)(a[7 * i + 2] & 0xff)) << 2) | ((short)(a[7 * i + 3] & 0x0f) << 10));
            this.coeffs[4 * i + 2] = (short)(((a[7 * i + 3] & 0xff) >>> 4) | (((short)(a[7 * i + 4] & 0xff) & 0xff) << 4) | ((short)(a[7 * i + 5] & 0x03) << 12));
            this.coeffs[4 * i + 3] = (short)(((a[7 * i + 5] & 0xff) >>> 2) | (((short)(a[7 * i + 6] & 0xff)) << 6));
        }

        // i=NTRU_PACK_DEG/4;
        if (params.packDegree() % 4 == 2)
        {
            this.coeffs[4 * i + 0] = (short)(a[7 * i + 0] | ((a[7 * i + 1] & 0x3f) << 8));
            this.coeffs[4 * i + 1] = (short)((a[7 * i + 1] >>> 6) | (((short)a[7 * i + 2]) << 2) | (((short)a[7 * i + 3] & 0x0f) << 10));
        }

        this.coeffs[params.n() - 1] = 0;
    }
}
