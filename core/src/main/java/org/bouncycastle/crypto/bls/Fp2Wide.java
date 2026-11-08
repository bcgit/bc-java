package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

/**
 * An unreduced element of Fp^2: both components are integers, possibly
 * negative, standing for their residues mod p. Products of reduced
 * {@link Fp2Element}s are formed here without reduction, summed, and reduced
 * once by {@link #reduce()}: "lazy reduction". In the Fp^6 / Fp^12 tower each
 * output coefficient is a sum of several Fp^2 products, so this halves the
 * number of reductions there, and a reduction costs several times what the
 * multiplication itself does.
 * <p>
 * Bounds: a product of two reduced elements has components in
 * {@code (-2p^2, 2p^2)}; the tower formulas add at most a handful of such
 * terms, staying far inside the {@code |x| < 2^WIDE_BITS} (about 97 p^2)
 * that {@link #reduce()} accepts. It checks that bound rather than assume it.
 */
final class Fp2Wide
{
    private static final BigInteger P = Fp2Element.P;

    private static final int K = P.bitLength();

    /** Inputs to {@link #reduceFp} must be below {@code 2^WIDE_BITS} in absolute value. */
    private static final int WIDE_BITS = 2 * K + 6;

    /** Barrett constant {@code floor(2^WIDE_BITS / p)}. */
    private static final BigInteger MU = BigInteger.ONE.shiftLeft(WIDE_BITS).divide(P);

    final BigInteger c0;
    final BigInteger c1;

    private Fp2Wide(BigInteger c0, BigInteger c1)
    {
        this.c0 = c0;
        this.c1 = c1;
    }

    /** {@code a * b}, unreduced, by Karatsuba: three multiplications. */
    static Fp2Wide mul(Fp2Element a, Fp2Element b)
    {
        BigInteger ac = a.c0().multiply(b.c0());
        BigInteger bd = a.c1().multiply(b.c1());
        BigInteger sum = a.c0().add(a.c1()).multiply(b.c0().add(b.c1()));
        return new Fp2Wide(ac.subtract(bd), sum.subtract(ac).subtract(bd));
    }

    /** {@code a^2 = (a0 + a1)(a0 - a1) + 2 a0 a1 * I}, unreduced: two multiplications. */
    static Fp2Wide square(Fp2Element a)
    {
        BigInteger a0 = a.c0(), a1 = a.c1();
        return new Fp2Wide(a0.add(a1).multiply(a0.subtract(a1)), a0.multiply(a1).shiftLeft(1));
    }

    Fp2Wide add(Fp2Wide o)
    {
        return new Fp2Wide(c0.add(o.c0), c1.add(o.c1));
    }

    Fp2Wide sub(Fp2Wide o)
    {
        return new Fp2Wide(c0.subtract(o.c0), c1.subtract(o.c1));
    }

    /** Multiply by the Fp^6 non-residue {@code 1 + I}: {@code (c0 - c1) + (c0 + c1) * I}. */
    Fp2Wide mulByNonResidue()
    {
        return new Fp2Wide(c0.subtract(c1), c0.add(c1));
    }

    /** The reduced element: one reduction per component. */
    Fp2Element reduce()
    {
        return Fp2Element.ofReduced(reduceFp(c0), reduceFp(c1));
    }

    /**
     * {@code x mod p} for {@code |x| < 2^WIDE_BITS}, by Barrett reduction of
     * {@code |x|}: the quotient estimate never exceeds {@code floor(|x| / p)}
     * and falls short by less than 3, so at most two corrective subtractions.
     */
    static BigInteger reduceFp(BigInteger x)
    {
        BigInteger m = x.abs();
        if (m.bitLength() > WIDE_BITS)
        {
            throw new IllegalStateException("lazy reduction bound exceeded");
        }
        BigInteger q = m.shiftRight(K - 1).multiply(MU).shiftRight(WIDE_BITS - K + 1);
        BigInteger r = m.subtract(q.multiply(P));
        while (r.compareTo(P) >= 0)
        {
            r = r.subtract(P);
        }
        return (x.signum() < 0 && r.signum() != 0) ? P.subtract(r) : r;
    }
}
