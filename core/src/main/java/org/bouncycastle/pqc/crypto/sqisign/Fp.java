package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;

/**
 * Storage cell for a GF(p) field element, held as a canonical
 * {@link BigInteger} in {@code [0, p)}.
 *
 * <p>The value is level-independent; the prime modulus lives on the
 * {@link GfField} / {@code FpLvlN} implementation that dispatches the
 * arithmetic, not on the cell itself.</p>
 */
final class Fp
{
    public BigInteger v;

    public Fp()
    {
        this.v = BigInteger.ZERO;
    }

    public Fp(BigInteger v)
    {
        this.v = v;
    }

    public Fp copy()
    {
        return new Fp(this.v);
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof Fp))
        {
            return false;
        }
        return ((Fp)o).v.equals(this.v);
    }

    public int hashCode()
    {
        return v.hashCode();
    }

    // ---- level-independent static helpers ----------------------------------

    /** Allocate a fresh zero cell. */
    public static Fp zero()
    {
        return new Fp();
    }

    /** Allocate a fresh one cell (canonical 1 is below every SQIsign prime). */
    public static Fp one()
    {
        return new Fp(BigInteger.ONE);
    }

    public static void setZero(Fp x)
    {
        x.v = BigInteger.ZERO;
    }

    public static void setOne(Fp x)
    {
        x.v = BigInteger.ONE;
    }

    /** Set {@code x} to a small unsigned long {@code val}. Canonical for
     *  {@code val < p}, which holds for all SQIsign primes (≥ 250 bits). */
    public static void setSmall(Fp x, long val)
    {
        x.v = BigInteger.valueOf(val);
    }

    public static void copy(Fp dst, Fp src)
    {
        dst.v = src.v;
    }

    /**
     * Conditional swap: swap {@code a} and {@code b} when {@code ctl != 0}.
     * <p>
     * Not constant-time: the value is a {@link BigInteger} and the swap is
     * branched on {@code ctl}. SQIsign's field arithmetic is BigInteger-based
     * and inherently variable-time (see {@link SQIsignSigner}), so this mirrors
     * the C reference's {@code fp_cswap} behaviourally without claiming its
     * constant-time property.
     * </p>
     */
    public static void cswap(Fp a, Fp b, int ctl)
    {
        if (ctl != 0)
        {
            BigInteger t = a.v;
            a.v = b.v;
            b.v = t;
        }
    }

    /**
     * Select: {@code d ← a1} if {@code ctl != 0}, else {@code d ← a0}. Branched
     * on {@code ctl}; see {@link #cswap(Fp, Fp, int)} for the constant-time
     * caveat.
     */
    public static void select(Fp d, Fp a0, Fp a1, int ctl)
    {
        d.v = (ctl == 0) ? a0.v : a1.v;
    }

    /** 0xFFFFFFFF if {@code a == 0}, else 0. */
    public static int isZero(Fp a)
    {
        return a.v.signum() == 0 ? 0xFFFFFFFF : 0;
    }

    /** 0xFFFFFFFF if {@code a == b}, else 0. */
    public static int isEqual(Fp a, Fp b)
    {
        return a.v.equals(b.v) ? 0xFFFFFFFF : 0;
    }
}
