package org.bouncycastle.pqc.math.ntru;

import org.bouncycastle.pqc.math.ntru.parameters.NTRUParameterSet;

/**
 * Polynomial for {@link org.bouncycastle.pqc.crypto.ntru}.
 */
public abstract class Polynomial
{
    /**
     * An array of coefficients
     */
    // TODO: maybe the maths library needs to move.
    public short[] coeffs;
    
    protected NTRUParameterSet params;

    public Polynomial(NTRUParameterSet params)
    {
        this.coeffs = new short[params.n()];
        this.params = params;
    }

    /**
     * @param x
     * @param y
     * @return -1 if x<0 and y<0; otherwise return 0
     * <p>
     * theory: if x and y are negative, MSB is 1. shifting right by 15 bits will produce 0xffff
     */
    // defined in poly_r2_inv.c and poly_s3_inv.c. both functions are identical
    static short bothNegativeMask(short x, short y)
    {
        return (short)((x & y) >>> 15);

    }

    // defined in poly_mod.c
    static short mod3(short a)
    {
        return (short)((a & 0xffff) % 3);
    }

    // defined in poly_s3_inv.c
    static byte mod3(byte a)
    {
        return (byte)((a & 0xff) % 3);
    }

    // defined in poly.h
    static int modQ(int x, int q)
    {
        return x % q;
    }


    // Defined in poly_mod.c
    public void mod3PhiN()
    {
        int n = this.params.n();
        for (int i = 0; i < n; i++)
        {
            this.coeffs[i] = mod3((short)(this.coeffs[i] + 2 * this.coeffs[n - 1]));
        }
    }

    // Defined in poly_mod.c
    public void modQPhiN()
    {
        int n = this.params.n();
        for (int i = 0; i < n; i++)
        {
            this.coeffs[i] = (short)(this.coeffs[i] - this.coeffs[n - 1]);
        }
    }


    /**
     * Pack Sq polynomial as a byte array
     *
     * @param len array length of packed polynomial
     * @return
     * @see <a href="https://ntru.org/f/ntru-20190330.pdf">NTRU specification</a> section 1.8.5
     */
    // defined in packq.c
    public abstract byte[] sqToBytes(int len);


    /**
     * Unpack a Sq polynomial
     *
     * @param a byte array of packed polynomial
     * @see <a href="https://ntru.org/f/ntru-20190330.pdf">NTRU specification</a> section 1.8.6
     */
    // defined in packq.c
    public abstract void sqFromBytes(byte[] a);


    /**
     * Pack a Rq0 polynomial as a byte array
     *
     * @param len array length of packed polynomial
     * @return
     * @see <a href="https://ntru.org/f/ntru-20190330.pdf">NTRU specification</a> section 1.8.3
     */
    // defined in packq.c
    public byte[] rqSumZeroToBytes(int len)
    {
        return this.sqToBytes(len);
    }


    /**
     * Unpack a Rq0 polynomial
     *
     * @param a byte array of packed polynomial
     * @see <a href="https://ntru.org/f/ntru-20190330.pdf">NTRU specification</a> section 1.8.4
     */
    // defined in packq.c
    public void rqSumZeroFromBytes(byte[] a)
    {
        int n = this.coeffs.length;

        this.sqFromBytes(a);
        this.coeffs[n - 1] = 0;
        for (int i = 0; i < params.packDegree(); i++)
        {
            this.coeffs[n - 1] -= this.coeffs[i];
        }
    }


    /**
     * Pack an S3 polynomial as a byte array
     *
     * @param messageSize array length of packed polynomial
     * @return
     * @see <a href="https://ntru.org/f/ntru-20190330.pdf">NTRU specification</a> section 1.8.7
     */
    // defined in pack3.c
    public byte[] s3ToBytes(int messageSize)
    {
        byte[] msg = new byte[messageSize];
        byte c;

        for (int i = 0; i < params.packDegree() / 5; i++)
        {
            c = (byte)(this.coeffs[5 * i + 4] & 255);
            c = (byte)(3 * c + this.coeffs[5 * i + 3] & 255);
            c = (byte)(3 * c + this.coeffs[5 * i + 2] & 255);
            c = (byte)(3 * c + this.coeffs[5 * i + 1] & 255);
            c = (byte)(3 * c + this.coeffs[5 * i + 0] & 255);
            msg[i] = c;
        }

        // if 5 does not divide NTRU_N-1
        if (params.packDegree() > (params.packDegree() / 5) * 5)
        {
            int i = params.packDegree() / 5;
            c = 0;
            for (int j = params.packDegree() - (5 * i) - 1; j >= 0; j--)
            {
                c = (byte)(3 * c + this.coeffs[5 * i + j] & 255);
            }
            msg[i] = c;
        }
        return msg;
    }

    /**
     * Unpack a S3 polynomial
     *
     * @param msg byte array of packed polynomial
     * @see <a href="https://ntru.org/f/ntru-20190330.pdf">NTRU specification</a> section 1.8.8
     */
    // defined in pack3.c
    public void s3FromBytes(byte[] msg)
    {
        int n = this.coeffs.length;
        byte c;
        for (int i = 0; i < params.packDegree() / 5; i++)
        {
            c = msg[i];
            this.coeffs[5 * i + 0] = c;
            this.coeffs[5 * i + 1] = (short)((c & 0xff) * 171 >>> 9);  // this is division by 3
            this.coeffs[5 * i + 2] = (short)((c & 0xff) * 57 >>> 9);  // division by 3^2
            this.coeffs[5 * i + 3] = (short)((c & 0xff) * 19 >>> 9);  // division by 3^3
            this.coeffs[5 * i + 4] = (short)((c & 0xff) * 203 >>> 14);  // etc.
        }

        if (params.packDegree() > (params.packDegree() / 5) * 5)
        {
            int i = params.packDegree() / 5;
            c = msg[i];
            for (int j = 0; (5 * i + j) < params.packDegree(); j++)
            {
                this.coeffs[5 * i + j] = c;
                c = (byte)((c & 0xff) * 171 >> 9);
            }
        }
        this.coeffs[n - 1] = 0;
        this.mod3PhiN();
    }


    // defined in poly.c
    public void sqMul(Polynomial a, Polynomial b)
    {
        this.rqMul(a, b);
        this.modQPhiN();
    }

    // defined in poly_rq_mul.c
    public void rqMul(Polynomial a, Polynomial b)
    {
        int n = this.coeffs.length;
        int k, i;
        for (k = 0; k < n; k++)
        {
            this.coeffs[k] = 0;
            for (i = 1; i < n - k; i++)
            {
                this.coeffs[k] += a.coeffs[k + i] * b.coeffs[n - i];
            }
            for (i = 0; i < k + 1; i++)
            {
                this.coeffs[k] += a.coeffs[k - i] * b.coeffs[i];
            }
        }
    }

    // defined in poly.c
    public void s3Mul(Polynomial a, Polynomial b)
    {
        this.rqMul(a, b);
        this.mod3PhiN();
    }

    /**
     * @param a
     * @see <a href="https://ntru.org/f/ntru-20190330.pdf">NTRU specification</a> section 1.9.3
     */
    // defined in poly_lift.c
    public abstract void lift(Polynomial a);

    // defined in poly_mod.c
    public void rqToS3(Polynomial a)
    {
        int n = this.coeffs.length;
        short flag;
        for (int i = 0; i < n; i++)
        {
            this.coeffs[i] = (short)modQ(a.coeffs[i] & 0xffff, params.q());
            flag = (short)(this.coeffs[i] >>> params.logQ() - 1);
            this.coeffs[i] += flag << (1 - (params.logQ() & 1));
        }
        this.mod3PhiN();
    }


    // defined in poly_r2_inv.c
    public abstract void r2Inv(Polynomial a);

    void r2Inv(Polynomial a, Polynomial f, Polynomial g, Polynomial v, Polynomial w)
    {
        int n = this.coeffs.length;
        int i, loop;
        short delta, sign, swap, t;

        w.coeffs[0] = 1;

        for (i = 0; i < n; ++i)
        {
            f.coeffs[i] = 1;
        }
        for (i = 0; i < n - 1; ++i)
        {
            g.coeffs[n - 2 - i] = (short)((a.coeffs[i] ^ a.coeffs[n - 1]) & 1);
        }
        g.coeffs[n - 1] = 0;

        delta = 1;

        for (loop = 0; loop < 2 * (n - 1) - 1; ++loop)
        {
            for (i = n - 1; i > 0; --i)
            {
                v.coeffs[i] = v.coeffs[i - 1];
            }
            v.coeffs[0] = 0;

            sign = (short)(g.coeffs[0] & f.coeffs[0]);
            swap = bothNegativeMask((short)-delta, (short)-g.coeffs[0]);
            delta ^= swap & (delta ^ -delta);
            delta++;

            for (i = 0; i < n; ++i)
            {
                t = (short)(swap & (f.coeffs[i] ^ g.coeffs[i]));
                f.coeffs[i] ^= t;
                g.coeffs[i] ^= t;
                t = (short)(swap & (v.coeffs[i] ^ w.coeffs[i]));
                v.coeffs[i] ^= t;
                w.coeffs[i] ^= t;
            }

            for (i = 0; i < n; ++i)
            {
                g.coeffs[i] = (short)(g.coeffs[i] ^ (sign & f.coeffs[i]));
            }
            for (i = 0; i < n; ++i)
            {
                w.coeffs[i] = (short)(w.coeffs[i] ^ (sign & v.coeffs[i]));
            }
            for (i = 0; i < n - 1; ++i)
            {
                g.coeffs[i] = g.coeffs[i + 1];
            }
            g.coeffs[n - 1] = 0;
        }

        for (i = 0; i < n - 1; ++i)
        {
            this.coeffs[i] = v.coeffs[n - 2 - i];
        }
        this.coeffs[n - 1] = 0;
    }

    // defined in poly.c
    public abstract void rqInv(Polynomial a);

    void rqInv(Polynomial a, Polynomial ai2, Polynomial b, Polynomial c, Polynomial s)
    {
        ai2.r2Inv(a);
        this.r2InvToRqInv(ai2, a, b, c, s);
    }

    // defined in poly.c
    private void r2InvToRqInv(Polynomial ai, Polynomial a, Polynomial b, Polynomial c, Polynomial s)
    {
        int n = this.coeffs.length;
        int i;
        for (i = 0; i < n; i++)
        {
            b.coeffs[i] = (short)-a.coeffs[i];
        }
        for (i = 0; i < n; i++)
        {
            this.coeffs[i] = ai.coeffs[i];
        }

        c.rqMul(this, b);
        c.coeffs[0] += 2;
        s.rqMul(c, this);

        c.rqMul(s, b);
        c.coeffs[0] += 2;
        this.rqMul(c, s);

        c.rqMul(this, b);
        c.coeffs[0] += 2;
        s.rqMul(c, this);

        c.rqMul(s, b);
        c.coeffs[0] += 2;
        this.rqMul(c, s);
    }

    // defined in poly_s3_inv.c
    public abstract void s3Inv(Polynomial a);

    void s3Inv(Polynomial a, Polynomial f, Polynomial g, Polynomial v, Polynomial w)
    {
        int n = this.coeffs.length;
        int i, loop;
        short delta, sign, swap, t;

        w.coeffs[0] = 1;

        for (i = 0; i < n; ++i)
        {
            f.coeffs[i] = 1;
        }
        for (i = 0; i < n - 1; ++i)
        {
            g.coeffs[n - 2 - i] = mod3((short)((a.coeffs[i] & 3) + 2 * (a.coeffs[n - 1] & 3)));
        }
        g.coeffs[n - 1] = 0;

        delta = 1;

        for (loop = 0; loop < 2 * (n - 1) - 1; ++loop)
        {
            for (i = n - 1; i > 0; --i)
            {
                v.coeffs[i] = v.coeffs[i - 1];
            }
            v.coeffs[0] = 0;

            sign = mod3((byte)(2 * g.coeffs[0] * f.coeffs[0]));
            swap = bothNegativeMask((short)-delta, (short)-g.coeffs[0]);
            delta ^= swap & (delta ^ -delta);
            delta++;

            for (i = 0; i < n; ++i)
            {
                t = (short)(swap & (f.coeffs[i] ^ g.coeffs[i]));
                f.coeffs[i] ^= t;
                g.coeffs[i] ^= t;
                t = (short)(swap & (v.coeffs[i] ^ w.coeffs[i]));
                v.coeffs[i] ^= t;
                w.coeffs[i] ^= t;
            }

            for (i = 0; i < n; ++i)
            {
                g.coeffs[i] = mod3((byte)(g.coeffs[i] + sign * f.coeffs[i]));
            }
            for (i = 0; i < n; ++i)
            {
                w.coeffs[i] = mod3((byte)(w.coeffs[i] + sign * v.coeffs[i]));
            }
            for (i = 0; i < n - 1; ++i)
            {
                g.coeffs[i] = g.coeffs[i + 1];
            }
            g.coeffs[n - 1] = 0;
        }

        sign = f.coeffs[0];
        for (i = 0; i < n - 1; ++i)
        {
            this.coeffs[i] = mod3((byte)(sign * v.coeffs[n - 2 - i]));
        }
        this.coeffs[n - 1] = 0;
    }


    public void z3ToZq()
    {
        int n = this.coeffs.length;
        for (int i = 0; i < n; i++)
        {
            this.coeffs[i] = (short)(this.coeffs[i] | ((-(this.coeffs[i] >>> 1)) & (params.q() - 1)));
        }
    }

    public void trinaryZqToZ3()
    {
        int n = this.coeffs.length;
        for (int i = 0; i < n; i++)
        {
            this.coeffs[i] = (short)modQ(this.coeffs[i] & 0xffff, params.q());
            this.coeffs[i] = (short)(3 & (this.coeffs[i] ^ (this.coeffs[i] >>> (params.logQ() - 1))));
        }
    }
}
