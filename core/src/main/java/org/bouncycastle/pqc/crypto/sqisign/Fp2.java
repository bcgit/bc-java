package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;

/**
 * Storage cell for a GF(p²) element {@code re + im·i} with {@code i² = -1}.
 *
 * <p>Shared across SQIsign levels; the prime modulus lives on the
 * {@link GfField} implementation that dispatches arithmetic, not on the
 * cell itself.</p>
 *
 * <p>Static helpers on this class are level-independent: they don't
 * perform modular reduction. Ops that need the prime ({@code add},
 * {@code mul}, {@code inv}, …) live on {@link GfField}.</p>
 */
final class Fp2
{
    public final Fp re;
    public final Fp im;

    public Fp2()
    {
        this.re = new Fp();
        this.im = new Fp();
    }

    public Fp2(Fp re, Fp im)
    {
        this.re = re.copy();
        this.im = im.copy();
    }

    public Fp2 copy()
    {
        return new Fp2(re, im);
    }

    // ---- level-independent static helpers ----------------------------------

    public static Fp2 zero()
    {
        return new Fp2();
    }

    public static Fp2 one()
    {
        Fp2 out = new Fp2();
        Fp.setOne(out.re);
        return out;
    }

    public static void setZero(Fp2 x)
    {
        Fp.setZero(x.re);
        Fp.setZero(x.im);
    }

    public static void setOne(Fp2 x)
    {
        Fp.setOne(x.re);
        Fp.setZero(x.im);
    }

    public static void setSmall(Fp2 x, long val)
    {
        Fp.setSmall(x.re, val);
        Fp.setZero(x.im);
    }

    public static void copy(Fp2 dst, Fp2 src)
    {
        Fp.copy(dst.re, src.re);
        Fp.copy(dst.im, src.im);
    }

    /** Conditional swap: if {@code ctl != 0}, swap {@code a} and {@code b}. */
    public static void cswap(Fp2 a, Fp2 b, int ctl)
    {
        Fp.cswap(a.re, b.re, ctl);
        Fp.cswap(a.im, b.im, ctl);
    }

    /** Constant-time select: {@code d ← a1} if {@code ctl != 0}, else {@code d ← a0}. */
    public static void select(Fp2 d, Fp2 a0, Fp2 a1, int ctl)
    {
        Fp.select(d.re, a0.re, a1.re, ctl);
        Fp.select(d.im, a0.im, a1.im, ctl);
    }

    /** 0xFFFFFFFF if both components are zero, else 0. */
    public static int isZero(Fp2 a)
    {
        return Fp.isZero(a.re) & Fp.isZero(a.im);
    }

    /** 0xFFFFFFFF if {@code a == b}, else 0. */
    public static int isEqual(Fp2 a, Fp2 b)
    {
        return Fp.isEqual(a.re, b.re) & Fp.isEqual(a.im, b.im);
    }

    /** 0xFFFFFFFF if {@code a == 1}, else 0. */
    public static int isOne(Fp2 a)
    {
        return (a.re.v.equals(BigInteger.ONE) && a.im.v.signum() == 0) ? 0xFFFFFFFF : 0;
    }
}
