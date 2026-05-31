package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;

/**
 * GF(p²) arithmetic for SQIsign level 3: the quadratic extension Fp(i) with
 * i² = -1. Java port of {@code src/gf/ref/lvlx/fp2.c}. The element a = re + im·i
 * is stored as two {@link Fp} components. The wire encoding produced by
 * {@link #encode(byte[], int, Fp2)} concatenates {@link FpLvl3#encode}(re)
 * followed by {@link FpLvl3#encode}(im) — 96 bytes total — matching the C
 * {@code fp2_encode}.
 */
final class Fp2Lvl3
{
    /** Byte-length of the canonical encoding (two Fp encodings concatenated). */
    public static final int ENCODED_BYTES = 2 * FpLvl3.ENCODED_BYTES;

    private Fp2Lvl3()
    {
    }

    // ---- constants ----------------------------------------------------------

    public static Fp2 zero()
    {
        return new Fp2();
    }

    public static Fp2 one()
    {
        Fp2 out = new Fp2();
        FpLvl3.setOne(out.re);
        return out;
    }

    public static void setZero(Fp2 x)
    {
        FpLvl3.setZero(x.re);
        FpLvl3.setZero(x.im);
    }

    public static void setOne(Fp2 x)
    {
        FpLvl3.setOne(x.re);
        FpLvl3.setZero(x.im);
    }

    public static void setSmall(Fp2 x, long val)
    {
        FpLvl3.setSmall(x.re, val);
        FpLvl3.setZero(x.im);
    }

    public static void copy(Fp2 x, Fp2 y)
    {
        FpLvl3.copy(x.re, y.re);
        FpLvl3.copy(x.im, y.im);
    }

    // ---- arithmetic ---------------------------------------------------------

    public static void add(Fp2 x, Fp2 y, Fp2 z)
    {
        FpLvl3.add(x.re, y.re, z.re);
        FpLvl3.add(x.im, y.im, z.im);
    }

    public static void addOne(Fp2 x, Fp2 y)
    {
        Fp one = FpLvl3.one();
        FpLvl3.add(x.re, y.re, one);
        FpLvl3.copy(x.im, y.im);
    }

    public static void sub(Fp2 x, Fp2 y, Fp2 z)
    {
        FpLvl3.sub(x.re, y.re, z.re);
        FpLvl3.sub(x.im, y.im, z.im);
    }

    public static void neg(Fp2 x, Fp2 y)
    {
        FpLvl3.neg(x.re, y.re);
        FpLvl3.neg(x.im, y.im);
    }

    /**
     * GF(p²) multiplication via Karatsuba on Fp:
     * (a+bi)(c+di) = (ac - bd) + ((a+b)(c+d) - ac - bd) i.
     * Mirrors {@code fp2_mul}.
     */
    public static void mul(Fp2 x, Fp2 y, Fp2 z)
    {
        Fp t0 = new Fp(), t1 = new Fp();
        Fp xRe = new Fp(), xIm = new Fp();

        FpLvl3.add(t0, y.re, y.im);
        FpLvl3.add(t1, z.re, z.im);
        FpLvl3.mul(t0, t0, t1);          // (a+b)(c+d)
        FpLvl3.mul(t1, y.im, z.im);      // bd
        FpLvl3.mul(xRe, y.re, z.re);     // ac
        FpLvl3.sub(xIm, t0, t1);
        FpLvl3.sub(xIm, xIm, xRe);       // (a+b)(c+d) - ac - bd
        FpLvl3.sub(xRe, xRe, t1);        // ac - bd

        FpLvl3.copy(x.re, xRe);
        FpLvl3.copy(x.im, xIm);
    }

    /**
     * GF(p²) squaring:
     * (a+bi)² = (a+b)(a-b) + 2ab·i.
     * Mirrors {@code fp2_sqr}.
     */
    public static void sqr(Fp2 x, Fp2 y)
    {
        Fp sum = new Fp(), diff = new Fp();
        Fp xRe = new Fp(), xIm = new Fp();

        FpLvl3.add(sum, y.re, y.im);
        FpLvl3.sub(diff, y.re, y.im);
        FpLvl3.mul(xIm, y.re, y.im);
        FpLvl3.add(xIm, xIm, xIm);       // 2ab
        FpLvl3.mul(xRe, sum, diff);      // (a+b)(a-b)

        FpLvl3.copy(x.re, xRe);
        FpLvl3.copy(x.im, xIm);
    }

    /**
     * In-place GF(p²) inverse: 1/(a+bi) = (a - bi) / (a² + b²).
     * Mirrors {@code fp2_inv}.
     */
    public static void inv(Fp2 x)
    {
        Fp t0 = new Fp(), t1 = new Fp();
        FpLvl3.sqr(t0, x.re);
        FpLvl3.sqr(t1, x.im);
        FpLvl3.add(t0, t0, t1);
        FpLvl3.inv(t0);
        FpLvl3.mul(x.re, x.re, t0);
        FpLvl3.mul(x.im, x.im, t0);
        FpLvl3.neg(x.im, x.im);
    }

    /** Multiply by a small (unsigned) integer. Mirrors {@code fp2_mul_small}. */
    public static void mulSmall(Fp2 x, Fp2 y, long n)
    {
        FpLvl3.mulSmall(x.re, y.re, n);
        FpLvl3.mulSmall(x.im, y.im, n);
    }

    public static void half(Fp2 x, Fp2 y)
    {
        FpLvl3.half(x.re, y.re);
        FpLvl3.half(x.im, y.im);
    }

    /**
     * Batched inversion using Montgomery's trick: invert n elements with one
     * Fp inverse and 3n - 3 multiplications. Mirrors {@code fp2_batched_inv}.
     */
    public static void batchedInv(Fp2[] x, int len)
    {
        if (len == 0)
        {
            return;
        }
        Fp2[] t1 = new Fp2[len];
        Fp2[] t2 = new Fp2[len];
        for (int i = 0; i < len; i++)
        {
            t1[i] = new Fp2();
            t2[i] = new Fp2();
        }

        copy(t1[0], x[0]);
        for (int i = 1; i < len; i++)
        {
            mul(t1[i], t1[i - 1], x[i]);
        }

        Fp2 inverse = new Fp2();
        copy(inverse, t1[len - 1]);
        inv(inverse);

        copy(t2[0], inverse);
        for (int i = 1; i < len; i++)
        {
            mul(t2[i], t2[i - 1], x[len - i]);
        }

        copy(x[0], t2[len - 1]);
        for (int i = 1; i < len; i++)
        {
            mul(x[i], t1[i - 1], t2[len - i - 1]);
        }
    }

    /**
     * Variable-time exponentiation via square-and-multiply. Mirrors
     * {@code fp2_pow_vartime}. Accepts the exponent as a non-negative
     * {@link BigInteger}; the bit-length is used in place of the C
     * {@code size * RADIX} loop bound.
     */
    public static void powVartime(Fp2 out, Fp2 x, BigInteger exp)
    {
        Fp2 acc = new Fp2();
        copy(acc, x);
        setOne(out);

        int nbits = exp.bitLength();
        for (int i = 0; i < nbits; i++)
        {
            if (exp.testBit(i))
            {
                mul(out, out, acc);
            }
            sqr(acc, acc);
        }
    }

    // ---- predicates ---------------------------------------------------------

    public static int isZero(Fp2 a)
    {
        return FpLvl3.isZero(a.re) & FpLvl3.isZero(a.im);
    }

    public static int isOne(Fp2 a)
    {
        Fp one = FpLvl3.one();
        return FpLvl3.isEqual(a.re, one) & FpLvl3.isZero(a.im);
    }

    public static int isEqual(Fp2 a, Fp2 b)
    {
        return FpLvl3.isEqual(a.re, b.re) & FpLvl3.isEqual(a.im, b.im);
    }

    public static int isSquare(Fp2 x)
    {
        Fp t0 = new Fp(), t1 = new Fp();
        FpLvl3.sqr(t0, x.re);
        FpLvl3.sqr(t1, x.im);
        FpLvl3.add(t0, t0, t1);
        return FpLvl3.isSquare(t0);
    }

    // ---- square root --------------------------------------------------------

    /**
     * In-place GF(p²) square root following the canonical-sign normalization
     * from Aardal et al. (eprint 2024/1563). Mirrors the C reference
     * {@code fp2_sqrt} including the deterministic sign selection based on
     * the encoded low bit of the candidate.
     */
    public static void sqrt(Fp2 a)
    {
        Fp x0 = new Fp(), x1 = new Fp(), t0 = new Fp(), t1 = new Fp();

        // x0 = delta = sqrt(re^2 + im^2)
        FpLvl3.sqr(x0, a.re);
        FpLvl3.sqr(x1, a.im);
        FpLvl3.add(x0, x0, x1);
        FpLvl3.sqrt(x0);
        // If im == 0, delta might be -re leaving x0 == 0 below — restore delta = re.
        FpLvl3.select(x0, x0, a.re, FpLvl3.isZero(a.im));

        // x0 = delta + re, t0 = 2*x0
        FpLvl3.add(x0, x0, a.re);
        FpLvl3.add(t0, x0, x0);

        // x1 = t0^((p-3)/4) — the progenitor
        FpLvl3.progenitor(x1, t0);

        // x0 *= x1, x1 *= im, t1 = (2*x0)^2
        FpLvl3.mul(x0, x0, x1);
        FpLvl3.mul(x1, x1, a.im);
        FpLvl3.add(t1, x0, x0);
        FpLvl3.sqr(t1, t1);

        // If t0 == t1 use (x0, x1); otherwise (x1, -x0).
        FpLvl3.sub(t0, t0, t1);
        int f = FpLvl3.isZero(t0);
        FpLvl3.neg(t1, x0);
        FpLvl3.copy(t0, x1);
        FpLvl3.select(t0, t0, x0, f);
        FpLvl3.select(t1, t1, x1, f);

        int t0IsZero = FpLvl3.isZero(t0);

        // Canonical-sign rule: encode, test low bit of LE byte 0.
        byte[] tmp = new byte[FpLvl3.ENCODED_BYTES];
        FpLvl3.encode(tmp, 0, t0);
        int t0IsOdd = -(tmp[0] & 1);
        FpLvl3.encode(tmp, 0, t1);
        int t1IsOdd = -(tmp[0] & 1);

        // Negate the output when t0 is odd, or t0 == 0 and t1 is odd.
        int negate = t0IsOdd | (t0IsZero & t1IsOdd);

        FpLvl3.neg(x0, t0);
        FpLvl3.select(a.re, t0, x0, negate);
        FpLvl3.neg(x0, t1);
        FpLvl3.select(a.im, t1, x0, negate);
    }

    /** Square root with verification: returns 0xFFFFFFFF iff a is a QR. */
    public static int sqrtVerify(Fp2 a)
    {
        Fp2 t0 = new Fp2(), t1 = new Fp2();
        copy(t0, a);
        sqrt(a);
        sqr(t1, a);
        return isEqual(t0, t1);
    }

    // ---- side-channel helpers ----------------------------------------------

    public static void select(Fp2 d, Fp2 a0, Fp2 a1, int ctl)
    {
        FpLvl3.select(d.re, a0.re, a1.re, ctl);
        FpLvl3.select(d.im, a0.im, a1.im, ctl);
    }

    // ---- encoding -----------------------------------------------------------

    public static void encode(byte[] dst, int off, Fp2 a)
    {
        FpLvl3.encode(dst, off, a.re);
        FpLvl3.encode(dst, off + FpLvl3.ENCODED_BYTES, a.im);
    }

    public static byte[] encode(Fp2 a)
    {
        byte[] out = new byte[ENCODED_BYTES];
        encode(out, 0, a);
        return out;
    }

    public static int decode(Fp2 d, byte[] src, int off)
    {
        int re = FpLvl3.decode(d.re, src, off);
        int im = FpLvl3.decode(d.im, src, off + FpLvl3.ENCODED_BYTES);
        return re & im;
    }
}
