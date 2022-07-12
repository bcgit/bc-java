package org.bouncycastle.pqc.math.ntru;

import org.bouncycastle.pqc.math.ntru.parameters.NTRUHPSParameterSet;

public class HPSPolynomial
    extends Polynomial
{
    public HPSPolynomial(NTRUHPSParameterSet params)
    {
        super(params);
    }

    @Override
    public byte[] sqToBytes(int len)
    {
        byte[] r = new byte[len];

        int i, j;
        short[] t = new short[8];
        for (i = 0; i < params.packDegree() / 8; i++)
        {
            for (j = 0; j < 8; j++)
            {
                t[j] = (short)modQ(this.coeffs[8 * i + j] & 0xffff, params.q());
            }
            r[11 * i + 0] = (byte)(t[0] & 0xff);
            r[11 * i + 1] = (byte)((t[0] >>> 8) | ((t[1] & 0x1f) << 3));
            r[11 * i + 2] = (byte)((t[1] >>> 5) | ((t[2] & 0x03) << 6));
            r[11 * i + 3] = (byte)((t[2] >>> 2) & 0xff);
            r[11 * i + 4] = (byte)((t[2] >>> 10) | ((t[3] & 0x7f) << 1));
            r[11 * i + 5] = (byte)((t[3] >>> 7) | ((t[4] & 0x0f) << 4));
            r[11 * i + 6] = (byte)((t[4] >>> 4) | ((t[5] & 0x01) << 7));
            r[11 * i + 7] = (byte)((t[5] >>> 1) & 0xff);
            r[11 * i + 8] = (byte)((t[5] >>> 9) | ((t[6] & 0x3f) << 2));
            r[11 * i + 9] = (byte)((t[6] >>> 6) | ((t[7] & 0x07) << 5));
            r[11 * i + 10] = (byte)(t[7] >>> 3);
        }

        for (j = 0; j < params.packDegree() - 8 * i; j++)
        {
            t[j] = (short)modQ(this.coeffs[8 * i + j] & 0xffff, params.q());
        }
        for (; j < 8; j++)
        {
            t[j] = 0;
        }

        switch (params.packDegree() & 0x07)
        {
        case 4:
        {
            r[11 * i + 0] = (byte)(t[0] & 0xff);
            r[11 * i + 1] = (byte)((t[0] >>> 8) | ((t[1] & 0x1f) << 3));
            r[11 * i + 2] = (byte)((t[1] >>> 5) | ((t[2] & 0x03) << 6));
            r[11 * i + 3] = (byte)((t[2] >>> 2) & 0xff);
            r[11 * i + 4] = (byte)((t[2] >>> 10) | ((t[3] & 0x7f) << 1));
            r[11 * i + 5] = (byte)((t[3] >>> 7) | ((t[4] & 0x0f) << 4));
            break;
        }
        case 2:
        {
            r[11 * i + 0] = (byte)(t[0] & 0xff);
            r[11 * i + 1] = (byte)((t[0] >>> 8) | ((t[1] & 0x1f) << 3));
            r[11 * i + 2] = (byte)((t[1] >>> 5) | ((t[2] & 0x03) << 6));
            break;
        }
        }
        return r;
    }

    @Override
    public void sqFromBytes(byte[] a)
    {
        int n = this.coeffs.length;
        int i;
        for (i = 0; i < params.packDegree() / 8; i++)
        {
            this.coeffs[8 * i + 0] = (short)(((a[11 * i + 0] & 0xff) >>> 0) | (((short)(a[11 * i + 1] & 0xff) & 0x07) << 8));
            this.coeffs[8 * i + 1] = (short)(((a[11 * i + 1] & 0xff) >>> 3) | (((short)(a[11 * i + 2] & 0xff) & 0x3f) << 5));
            this.coeffs[8 * i + 2] = (short)(((a[11 * i + 2] & 0xff) >>> 6) | (((short)(a[11 * i + 3] & 0xff) & 0xff) << 2) | (((short)(a[11 * i + 4] & 0xff) & 0x01) << 10));
            this.coeffs[8 * i + 3] = (short)(((a[11 * i + 4] & 0xff) >>> 1) | (((short)(a[11 * i + 5] & 0xff) & 0x0f) << 7));
            this.coeffs[8 * i + 4] = (short)(((a[11 * i + 5] & 0xff) >>> 4) | (((short)(a[11 * i + 6] & 0xff) & 0x7f) << 4));
            this.coeffs[8 * i + 5] = (short)(((a[11 * i + 6] & 0xff) >>> 7) | (((short)(a[11 * i + 7] & 0xff) & 0xff) << 1) | (((short)(a[11 * i + 8] & 0xff) & 0x03) << 9));
            this.coeffs[8 * i + 6] = (short)(((a[11 * i + 8] & 0xff) >>> 2) | (((short)(a[11 * i + 9] & 0xff) & 0x1f) << 6));
            this.coeffs[8 * i + 7] = (short)(((a[11 * i + 9] & 0xff) >>> 5) | (((short)(a[11 * i + 10] & 0xff) & 0xff) << 3));
        }

        switch (params.packDegree() & 0x07)
        {
        case 4:
        {
            this.coeffs[8 * i + 0] = (short)(((a[11 * i + 0] & 0xff) >>> 0) | (((short)(a[11 * i + 1] & 0xff) & 0x07) << 8));
            this.coeffs[8 * i + 1] = (short)(((a[11 * i + 1] & 0xff) >>> 3) | (((short)(a[11 * i + 2] & 0xff) & 0x3f) << 5));
            this.coeffs[8 * i + 2] = (short)(((a[11 * i + 2] & 0xff) >>> 6) | (((short)(a[11 * i + 3] & 0xff) & 0xff) << 2) | (((short)(a[11 * i + 4] & 0xff) & 0x01) << 10));
            this.coeffs[8 * i + 3] = (short)(((a[11 * i + 4] & 0xff) >>> 1) | (((short)(a[11 * i + 5] & 0xff) & 0x0f) << 7));
            break;
        }
        case 2:
        {
            this.coeffs[8 * i + 0] = (short)(((a[11 * i + 0] & 0xff) >>> 0) | (((short)(a[11 * i + 1] & 0xff) & 0x07) << 8));
            this.coeffs[8 * i + 1] = (short)(((a[11 * i + 1] & 0xff) >>> 3) | (((short)(a[11 * i + 2] & 0xff) & 0x3f) << 5));
            break;
        }
        }
        this.coeffs[n - 1] = 0;
    }

    @Override
    public void lift(Polynomial a)
    {
        int n = this.coeffs.length;
        System.arraycopy(a.coeffs, 0, this.coeffs, 0, n);
        this.z3ToZq();
    }

    @Override
    public void r2Inv(Polynomial a)
    {
        HPSPolynomial f = new HPSPolynomial((NTRUHPSParameterSet)this.params);
        HPSPolynomial g = new HPSPolynomial((NTRUHPSParameterSet)this.params);
        HPSPolynomial v = new HPSPolynomial((NTRUHPSParameterSet)this.params);
        HPSPolynomial w = new HPSPolynomial((NTRUHPSParameterSet)this.params);
        this.r2Inv(a, f, g, v, w);
    }

    @Override
    public void rqInv(Polynomial a)
    {
        HPSPolynomial ai2 = new HPSPolynomial((NTRUHPSParameterSet)this.params);
        HPSPolynomial b = new HPSPolynomial((NTRUHPSParameterSet)this.params);
        HPSPolynomial c = new HPSPolynomial((NTRUHPSParameterSet)this.params);
        HPSPolynomial s = new HPSPolynomial((NTRUHPSParameterSet)this.params);
        this.rqInv(a, ai2, b, c, s);
    }

    @Override
    public void s3Inv(Polynomial a)
    {
        HPSPolynomial f = new HPSPolynomial((NTRUHPSParameterSet)this.params);
        HPSPolynomial g = new HPSPolynomial((NTRUHPSParameterSet)this.params);
        HPSPolynomial v = new HPSPolynomial((NTRUHPSParameterSet)this.params);
        HPSPolynomial w = new HPSPolynomial((NTRUHPSParameterSet)this.params);
        this.s3Inv(a, f, g, v, w);
    }


}
