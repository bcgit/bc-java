package org.bouncycastle.pqc.math.ntru;

import org.bouncycastle.pqc.math.ntru.parameters.NTRUHRSSParameterSet;

public class HRSSPolynomial
    extends Polynomial
{
    public HRSSPolynomial(NTRUHRSSParameterSet params)
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

            r[13 * i + 0] = (byte)(t[0] & 0xff);
            r[13 * i + 1] = (byte)((t[0] >>> 8) | ((t[1] & 0x07) << 5));
            r[13 * i + 2] = (byte)((t[1] >>> 3) & 0xff);
            r[13 * i + 3] = (byte)((t[1] >>> 11) | ((t[2] & 0x3f) << 2));
            r[13 * i + 4] = (byte)((t[2] >>> 6) | ((t[3] & 0x01) << 7));
            r[13 * i + 5] = (byte)((t[3] >>> 1) & 0xff);
            r[13 * i + 6] = (byte)((t[3] >>> 9) | ((t[4] & 0x0f) << 4));
            r[13 * i + 7] = (byte)((t[4] >>> 4) & 0xff);
            r[13 * i + 8] = (byte)((t[4] >>> 12) | ((t[5] & 0x7f) << 1));
            r[13 * i + 9] = (byte)((t[5] >>> 7) | ((t[6] & 0x03) << 6));
            r[13 * i + 10] = (byte)((t[6] >>> 2) & 0xff);
            r[13 * i + 11] = (byte)((t[6] >>> 10) | ((t[7] & 0x1f) << 3));
            r[13 * i + 12] = (byte)((t[7] >>> 5));
        }

        for (j = 0; j < params.packDegree() - 8 * i; j++)
        {
            t[j] = (short)modQ(this.coeffs[8 * i + j] & 0xffff, params.q());
        }
        for (; j < 8; j++)
        {
            t[j] = 0;
        }

        switch (params.packDegree() - 8 * (params.packDegree() / 8))
        {
        case 4:
        {
            r[13 * i + 0] = (byte)(t[0] & 0xff);
            r[13 * i + 1] = (byte)((t[0] >>> 8) | ((t[1] & 0x07) << 5));
            r[13 * i + 2] = (byte)((t[1] >>> 3) & 0xff);
            r[13 * i + 3] = (byte)((t[1] >>> 11) | ((t[2] & 0x3f) << 2));
            r[13 * i + 4] = (byte)((t[2] >>> 6) | ((t[3] & 0x01) << 7));
            r[13 * i + 5] = (byte)((t[3] >>> 1) & 0xff);
            r[13 * i + 6] = (byte)((t[3] >>> 9) | ((t[4] & 0x0f) << 4));
        }
        case 2:
        {
            r[13 * i + 0] = (byte)(t[0] & 0xff);
            r[13 * i + 1] = (byte)((t[0] >>> 8) | ((t[1] & 0x07) << 5));
            r[13 * i + 2] = (byte)((t[1] >>> 3) & 0xff);
            r[13 * i + 3] = (byte)((t[1] >>> 11) | ((t[2] & 0x3f) << 2));
        }
        }

        return r;
    }

    @Override
    public void sqFromBytes(byte[] a)
    {
        int i;
        for (i = 0; i < params.packDegree() / 8; i++)
        {
            this.coeffs[8 * i + 0] = (short)((a[13 * i + 0] & 0xff) | (((short)(a[13 * i + 1] & 0xff) & 0x1f) << 8));
            this.coeffs[8 * i + 1] = (short)(((a[13 * i + 1] & 0xff) >>> 5) | (((short)(a[13 * i + 2] & 0xff)) << 3) | (((short)(a[13 * i + 3] & 0xff) & 0x03) << 11));
            this.coeffs[8 * i + 2] = (short)(((a[13 * i + 3] & 0xff) >>> 2) | (((short)(a[13 * i + 4] & 0xff) & 0x7f) << 6));
            this.coeffs[8 * i + 3] = (short)(((a[13 * i + 4] & 0xff) >>> 7) | (((short)(a[13 * i + 5] & 0xff)) << 1) | (((short)(a[13 * i + 6] & 0xff) & 0x0f) << 9));
            this.coeffs[8 * i + 4] = (short)(((a[13 * i + 6] & 0xff) >>> 4) | (((short)(a[13 * i + 7] & 0xff)) << 4) | (((short)(a[13 * i + 8] & 0xff) & 0x01) << 12));
            this.coeffs[8 * i + 5] = (short)(((a[13 * i + 8] & 0xff) >>> 1) | (((short)(a[13 * i + 9] & 0xff) & 0x3f) << 7));
            this.coeffs[8 * i + 6] = (short)(((a[13 * i + 9] & 0xff) >>> 6) | (((short)(a[13 * i + 10] & 0xff)) << 2) | (((short)(a[13 * i + 11] & 0xff) & 0x07) << 10));
            this.coeffs[8 * i + 7] = (short)(((a[13 * i + 11] & 0xff) >>> 3) | (((short)(a[13 * i + 12] & 0xff)) << 5));
        }

        switch (params.packDegree() & 0x07)
        {
        case 4:
        {
            this.coeffs[8 * i + 0] = (short)((a[13 * i + 0] & 0xff) | (((short)(a[13 * i + 1] & 0xff) & 0x1f) << 8));
            this.coeffs[8 * i + 1] = (short)(((a[13 * i + 1] & 0xff) >>> 5) | (((short)(a[13 * i + 2] & 0xff)) << 3) | (((short)(a[13 * i + 3] & 0xff) & 0x03) << 11));
            this.coeffs[8 * i + 2] = (short)(((a[13 * i + 3] & 0xff) >>> 2) | (((short)(a[13 * i + 4] & 0xff) & 0x7f) << 6));
            this.coeffs[8 * i + 3] = (short)(((a[13 * i + 4] & 0xff) >>> 7) | (((short)(a[13 * i + 5] & 0xff)) << 1) | (((short)(a[13 * i + 6] & 0xff) & 0x0f) << 9));
            break;
        }
        case 2:
        {
            this.coeffs[8 * i + 0] = (short)((a[13 * i + 0] & 0xff) | (((short)(a[13 * i + 1] & 0xff) & 0x1f) << 8));
            this.coeffs[8 * i + 1] = (short)(((a[13 * i + 1] & 0xff) >>> 5) | (((short)(a[13 * i + 2] & 0xff)) << 3) | (((short)(a[13 * i + 3] & 0xff) & 0x03) << 11));
            break;
        }
        }

        this.coeffs[params.n() - 1] = 0;
    }

    @Override
    public void lift(Polynomial a)
    {
        int n = this.coeffs.length;

        /* NOTE: Assumes input is in {0,1,2}^N */
        /*       Produces output in [0,Q-1]^N */
        int i;
        HRSSPolynomial b = new HRSSPolynomial((NTRUHRSSParameterSet)this.params);
        short t, zj;

        /* Define z by <z*x^i, x-1> = delta_{i,0} mod 3:      */
        /*   t      = -1/N mod p = -N mod 3                   */
        /*   z[0]   = 2 - t mod 3                             */
        /*   z[1]   = 0 mod 3                                 */
        /*   z[j]   = z[j-1] + t mod 3                        */
        /* We'll compute b = a/(x-1) mod (3, Phi) using       */
        /*   b[0] = <z, a>, b[1] = <z*x,a>, b[2] = <z*x^2,a>  */
        /*   b[i] = b[i-3] - (a[i] + a[i-1] + a[i-2])         */
        t = (short)(3 - (n % 3));
        b.coeffs[0] = (short)(a.coeffs[0] * (2 - t) + a.coeffs[1] * 0 + a.coeffs[2] * t);
        b.coeffs[1] = (short)(a.coeffs[1] * (2 - t) + a.coeffs[2] * 0);
        b.coeffs[2] = (short)(a.coeffs[2] * (2 - t));

        zj = 0; /* z[1] */
        for (i = 3; i < n; i++)
        {
            b.coeffs[0] += a.coeffs[i] * (zj + 2 * t);
            b.coeffs[1] += a.coeffs[i] * (zj + t);
            b.coeffs[2] += a.coeffs[i] * zj;
            zj = (short)((zj + t) % 3);
        }
        b.coeffs[1] += a.coeffs[0] * (zj + t);
        b.coeffs[2] += a.coeffs[0] * zj;
        b.coeffs[2] += a.coeffs[1] * (zj + t);
        for (i = 3; i < n; i++)
        {
            b.coeffs[i] = (short)(b.coeffs[i - 3] + 2 * (a.coeffs[i] + a.coeffs[i - 1] + a.coeffs[i - 2]));
        }

        /* Finish reduction mod Phi by subtracting Phi * b[N-1] */
        b.mod3PhiN();

        /* Switch from {0,1,2} to {0,1,q-1} coefficient representation */
        b.z3ToZq();

        /* Multiply by (x-1) */
        this.coeffs[0] = (short)-b.coeffs[0];
        for (i = 0; i < n - 1; i++)
        {
            this.coeffs[i + 1] = (short)(b.coeffs[i] - b.coeffs[i + 1]);
        }
    }

    @Override
    public void r2Inv(Polynomial a)
    {
        HRSSPolynomial f = new HRSSPolynomial((NTRUHRSSParameterSet)this.params);
        HRSSPolynomial g = new HRSSPolynomial((NTRUHRSSParameterSet)this.params);
        HRSSPolynomial v = new HRSSPolynomial((NTRUHRSSParameterSet)this.params);
        HRSSPolynomial w = new HRSSPolynomial((NTRUHRSSParameterSet)this.params);
        this.r2Inv(a, f, g, v, w);
    }

    @Override
    public void rqInv(Polynomial a)
    {
        HRSSPolynomial ai2 = new HRSSPolynomial((NTRUHRSSParameterSet)this.params);
        HRSSPolynomial b = new HRSSPolynomial((NTRUHRSSParameterSet)this.params);
        HRSSPolynomial c = new HRSSPolynomial((NTRUHRSSParameterSet)this.params);
        HRSSPolynomial s = new HRSSPolynomial((NTRUHRSSParameterSet)this.params);
        this.rqInv(a, ai2, b, c, s);
    }

    @Override
    public void s3Inv(Polynomial a)
    {
        HRSSPolynomial f = new HRSSPolynomial((NTRUHRSSParameterSet)this.params);
        HRSSPolynomial g = new HRSSPolynomial((NTRUHRSSParameterSet)this.params);
        HRSSPolynomial v = new HRSSPolynomial((NTRUHRSSParameterSet)this.params);
        HRSSPolynomial w = new HRSSPolynomial((NTRUHRSSParameterSet)this.params);
        this.s3Inv(a, f, g, v, w);
    }
}
