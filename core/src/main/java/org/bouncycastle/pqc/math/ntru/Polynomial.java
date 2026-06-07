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
        s3ToBytes(msg, 0);
        return msg;
    }

    public void s3ToBytes(byte[] msg, int msgOff)
    {
        int degree = params.packDegree(), limit = degree - 5;

        int i = 0;
        while (i <= limit)
        {
            int c0 = (coeffs[i + 0] & 0xFF);
            int c1 = (coeffs[i + 1] & 0xFF) * 3;
            int c2 = (coeffs[i + 2] & 0xFF) * 9;
            int c3 = (coeffs[i + 3] & 0xFF) * 27;
            int c4 = (coeffs[i + 4] & 0xFF) * 81;

            msg[msgOff++] = (byte)(c0 + c1 + c2 + c3 + c4);
            i += 5;
        }

        if (i < degree)
        {
            int j = degree - 1;
            int c = coeffs[j] & 0xFF;

            while (--j >= i)
            {
                c *= 3;
                c += coeffs[j] & 0xFF;
            }

            msg[msgOff++] = (byte)c;
        }
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

    // Karatsuba base-case size: below this, the recursion bottoms out into the schoolbook
    // linear convolution. Tuned empirically across the parameter sets (n = 509..1373).
    private static final int RQ_MUL_THRESHOLD = 48;

    // defined in poly_rq_mul.c
    public void rqMul(Polynomial a, Polynomial b)
    {
        // rqMul is multiplication in Z[x]/(x^n - 1) (cyclic convolution), with the result kept
        // only modulo 2^16 in each short (the caller reduces mod q / mod Phi_n afterwards).
        //
        // The reference computes this with a Karatsuba/Toom-Cook split; the original Java port
        // used a naive O(n^2) schoolbook. We replace it with recursive Karatsuba (O(n^1.585)),
        // which is division-free - pure +/-/* - so it stays byte-identical to the schoolbook
        // result modulo 2^16 even though intermediates overflow int: every operation is closed
        // under arithmetic mod 2^32, and 2^16 divides 2^32, so the low 16 bits of each folded
        // coefficient are preserved. (Toom-Cook is deliberately NOT used: its interpolation
        // divides by 2, which is not invertible mod 2^16, so it cannot be made byte-identical
        // here without full-precision interpolation.)
        //
        // The access pattern is loop-counter-indexed throughout (no secret-derived index, branch,
        // or table), so the constant-time posture of the schoolbook kernel is preserved.
        short[] aCoeffs = a.coeffs, bCoeffs = b.coeffs, cCoeffs = this.coeffs;
        int n = cCoeffs.length;

        int[] ai = new int[n];
        int[] bi = new int[n];
        for (int i = 0; i < n; i++)
        {
            ai[i] = aCoeffs[i];
            bi[i] = bCoeffs[i];
        }

        // Linear convolution of length 2n-1 (index 2n-1 is left zero so the fold below needs no
        // bounds branch); t is the Karatsuba scratch workspace (the recursion uses up to ~8n).
        int[] lin = new int[2 * n];
        int[] t = new int[9 * n];
        kMul(lin, 0, ai, 0, bi, 0, n, t, 0);

        // Fold the linear convolution into the cyclic ring: x^n == 1 means coefficient (k+n)
        // wraps onto coefficient k. Truncate to short once, here.
        for (int k = 0; k < n; k++)
        {
            cCoeffs[k] = (short)(lin[k] + lin[k + n]);
        }
    }

    /**
     * Recursive Karatsuba linear convolution over the integers (taken mod 2^32 by natural int
     * overflow). Writes exactly {@code 2*len - 1} entries to {@code r[rOff..]}; uses {@code t[tOff..]}
     * as scratch. {@code r} and {@code t} may be the same backing array, provided the written
     * result range and the scratch range are disjoint (the callers guarantee this).
     */
    private static void kMul(int[] r, int rOff, int[] a, int aOff, int[] b, int bOff, int len, int[] t, int tOff)
    {
        if (len <= RQ_MUL_THRESHOLD)
        {
            int outLen = 2 * len - 1;
            for (int p = 0; p < outLen; p++)
            {
                r[rOff + p] = 0;
            }
            for (int i = 0; i < len; i++)
            {
                int ai = a[aOff + i];
                int base = rOff + i;
                for (int j = 0; j < len; j++)
                {
                    r[base + j] += ai * b[bOff + j];
                }
            }
            return;
        }

        int m = (len + 1) >> 1;     // low-half length
        int hi = len - m;           // high-half length (hi <= m)

        // Carve the scratch for this level out of t[tOff..]; deeper recursions get t[next..].
        int saOff = tOff;                   // sa = a_lo + a_hi   (length m)
        int sbOff = saOff + m;              // sb = b_lo + b_hi   (length m)
        int z0Off = sbOff + m;              // z0 = a_lo * b_lo   (length 2m-1)
        int z2Off = z0Off + (2 * m - 1);    // z2 = a_hi * b_hi   (length 2hi-1)
        int z1Off = z2Off + (2 * hi - 1);   // z1 = sa * sb       (length 2m-1)
        int next = z1Off + (2 * m - 1);

        for (int i = 0; i < m; i++)
        {
            t[saOff + i] = a[aOff + i];
            t[sbOff + i] = b[bOff + i];
        }
        for (int i = 0; i < hi; i++)
        {
            t[saOff + i] += a[aOff + m + i];
            t[sbOff + i] += b[bOff + m + i];
        }

        kMul(t, z0Off, a, aOff, b, bOff, m, t, next);
        kMul(t, z2Off, a, aOff + m, b, bOff + m, hi, t, next);
        kMul(t, z1Off, t, saOff, t, sbOff, m, t, next);

        // z1 -= z0 + z2 (the Karatsuba middle term)
        for (int i = 0; i < 2 * m - 1; i++)
        {
            t[z1Off + i] -= t[z0Off + i];
        }
        for (int i = 0; i < 2 * hi - 1; i++)
        {
            t[z1Off + i] -= t[z2Off + i];
        }

        // Assemble: r = z0 + (z1 << m) + (z2 << 2m).
        int outLen = 2 * len - 1;
        for (int p = 0; p < outLen; p++)
        {
            r[rOff + p] = 0;
        }
        for (int i = 0; i < 2 * m - 1; i++)
        {
            r[rOff + i] += t[z0Off + i];
        }
        for (int i = 0; i < 2 * hi - 1; i++)
        {
            r[rOff + 2 * m + i] += t[z2Off + i];
        }
        for (int i = 0; i < 2 * m - 1; i++)
        {
            r[rOff + m + i] += t[z1Off + i];
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
    public void r2Inv(Polynomial a)
    {
        Polynomial f = this.params.createPolynomial();
        Polynomial g = this.params.createPolynomial();
        Polynomial v = this.params.createPolynomial();
        Polynomial w = this.params.createPolynomial();
        this.r2Inv(a, f, g, v, w);
    }

    // defined in poly.c
    public void rqInv(Polynomial a)
    {
        Polynomial ai2 = this.params.createPolynomial();
        Polynomial b = this.params.createPolynomial();
        Polynomial c = this.params.createPolynomial();
        Polynomial s = this.params.createPolynomial();
        this.rqInv(a, ai2, b, c, s);
    }

    // defined in poly_s3_inv.c
    public void s3Inv(Polynomial a)
    {
        Polynomial f = this.params.createPolynomial();
        Polynomial g = this.params.createPolynomial();
        Polynomial v = this.params.createPolynomial();
        Polynomial w = this.params.createPolynomial();
        this.s3Inv(a, f, g, v, w);
    }

    void r2Inv(Polynomial a, Polynomial f, Polynomial g, Polynomial v, Polynomial w)
    {
        // Hoist the per-Polynomial coefficient arrays into locals. The array identities are
        // stable across the method (the constant-time swap only exchanges contents, never the
        // backing arrays), so this is a byte-identical refactor that keeps the arrays
        // register-resident and lets the JIT auto-vectorise the inner XOR/AND loops.
        short[] ac = a.coeffs, fc = f.coeffs, gc = g.coeffs, vc = v.coeffs, wc = w.coeffs, rc = this.coeffs;
        int n = rc.length;
        int i, loop;
        short delta, sign, swap, t;

        wc[0] = 1;

        for (i = 0; i < n; ++i)
        {
            fc[i] = 1;
        }
        for (i = 0; i < n - 1; ++i)
        {
            gc[n - 2 - i] = (short)((ac[i] ^ ac[n - 1]) & 1);
        }
        gc[n - 1] = 0;

        delta = 1;

        for (loop = 0; loop < 2 * (n - 1) - 1; ++loop)
        {
            for (i = n - 1; i > 0; --i)
            {
                vc[i] = vc[i - 1];
            }
            vc[0] = 0;

            sign = (short)(gc[0] & fc[0]);
            swap = bothNegativeMask((short)-delta, (short)-gc[0]);
            delta ^= swap & (delta ^ -delta);
            delta++;

            for (i = 0; i < n; ++i)
            {
                t = (short)(swap & (fc[i] ^ gc[i]));
                fc[i] ^= t;
                gc[i] ^= t;
                t = (short)(swap & (vc[i] ^ wc[i]));
                vc[i] ^= t;
                wc[i] ^= t;
            }

            for (i = 0; i < n; ++i)
            {
                gc[i] = (short)(gc[i] ^ (sign & fc[i]));
            }
            for (i = 0; i < n; ++i)
            {
                wc[i] = (short)(wc[i] ^ (sign & vc[i]));
            }
            for (i = 0; i < n - 1; ++i)
            {
                gc[i] = gc[i + 1];
            }
            gc[n - 1] = 0;
        }

        for (i = 0; i < n - 1; ++i)
        {
            rc[i] = vc[n - 2 - i];
        }
        rc[n - 1] = 0;
    }

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

    void s3Inv(Polynomial a, Polynomial f, Polynomial g, Polynomial v, Polynomial w)
    {
        // See r2Inv: byte-identical hoist of the stable coefficient arrays into locals.
        short[] ac = a.coeffs, fc = f.coeffs, gc = g.coeffs, vc = v.coeffs, wc = w.coeffs, rc = this.coeffs;
        int n = rc.length;
        int i, loop;
        short delta, sign, swap, t;

        wc[0] = 1;

        for (i = 0; i < n; ++i)
        {
            fc[i] = 1;
        }
        for (i = 0; i < n - 1; ++i)
        {
            gc[n - 2 - i] = mod3((short)((ac[i] & 3) + 2 * (ac[n - 1] & 3)));
        }
        gc[n - 1] = 0;

        delta = 1;

        for (loop = 0; loop < 2 * (n - 1) - 1; ++loop)
        {
            for (i = n - 1; i > 0; --i)
            {
                vc[i] = vc[i - 1];
            }
            vc[0] = 0;

            sign = mod3((byte)(2 * gc[0] * fc[0]));
            swap = bothNegativeMask((short)-delta, (short)-gc[0]);
            delta ^= swap & (delta ^ -delta);
            delta++;

            for (i = 0; i < n; ++i)
            {
                t = (short)(swap & (fc[i] ^ gc[i]));
                fc[i] ^= t;
                gc[i] ^= t;
                t = (short)(swap & (vc[i] ^ wc[i]));
                vc[i] ^= t;
                wc[i] ^= t;
            }

            for (i = 0; i < n; ++i)
            {
                gc[i] = mod3((byte)(gc[i] + sign * fc[i]));
            }
            for (i = 0; i < n; ++i)
            {
                wc[i] = mod3((byte)(wc[i] + sign * vc[i]));
            }
            for (i = 0; i < n - 1; ++i)
            {
                gc[i] = gc[i + 1];
            }
            gc[n - 1] = 0;
        }

        sign = fc[0];
        for (i = 0; i < n - 1; ++i)
        {
            rc[i] = mod3((byte)(sign * vc[n - 2 - i]));
        }
        rc[n - 1] = 0;
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
