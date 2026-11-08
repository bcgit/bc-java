package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

import org.bouncycastle.math.ec.WNafUtil;

/**
 * Immutable element of {@code Fp^12 = Fp^6[w] / (w^2 - v)}, the outer level
 * of the BLS12-381 pairing field tower.
 * <p>
 * An element is represented as {@code c0 + c1*w} where each c_i is an Fp^6
 * element. The relation {@code w^2 = v} (the polynomial generator of Fp^6)
 * gives a clean Karatsuba-style multiplication.
 */
public final class Fp12Element
{
    public static final Fp12Element ZERO = new Fp12Element(Fp6Element.ZERO, Fp6Element.ZERO);
    public static final Fp12Element ONE = new Fp12Element(Fp6Element.ONE, Fp6Element.ZERO);

    /**
     * Frobenius<sup>2</sup> coefficient for the {@code w} basis:
     * {@code (1 + I)^((p^2 - 1) / 6)} in Fp&sup2;. Used in
     * {@link #frobeniusSquared()}.
     */
    private static final Fp2Element FROB_SQ_W;

    /**
     * Frobenius coefficient for the {@code w} basis: {@code (1 + I)^((p - 1) / 6)}
     * in Fp&sup2;.
     */
    private static final Fp2Element FROB_W;

    static
    {
        BigInteger pSqMinus1Over6 = Fp2Element.P.pow(2)
            .subtract(BigInteger.ONE)
            .divide(BigInteger.valueOf(6));
        FROB_SQ_W = Fp6Element.NON_RESIDUE.modPow(pSqMinus1Over6);

        BigInteger pMinus1Over6 = Fp2Element.P
            .subtract(BigInteger.ONE)
            .divide(BigInteger.valueOf(6));
        FROB_W = Fp6Element.NON_RESIDUE.modPow(pMinus1Over6);
    }

    private final Fp6Element c0;
    private final Fp6Element c1;

    private Fp12Element(Fp6Element c0, Fp6Element c1)
    {
        this.c0 = c0;
        this.c1 = c1;
    }

    public static Fp12Element of(Fp6Element c0, Fp6Element c1)
    {
        return new Fp12Element(c0, c1);
    }

    public static Fp12Element fromFp6(Fp6Element c0)
    {
        return new Fp12Element(c0, Fp6Element.ZERO);
    }

    public Fp6Element c0()
    {
        return c0;
    }

    public Fp6Element c1()
    {
        return c1;
    }

    public boolean isZero()
    {
        return c0.isZero() && c1.isZero();
    }

    public Fp12Element add(Fp12Element other)
    {
        return new Fp12Element(c0.add(other.c0), c1.add(other.c1));
    }

    public Fp12Element sub(Fp12Element other)
    {
        return new Fp12Element(c0.sub(other.c0), c1.sub(other.c1));
    }

    public Fp12Element neg()
    {
        return new Fp12Element(c0.neg(), c1.neg());
    }

    /**
     * Karatsuba multiplication using {@code w^2 = v}:
     * <pre>
     *   (a0 + a1*w)(b0 + b1*w) = (a0*b0 + a1*b1*v) + ((a0+a1)(b0+b1) - a0*b0 - a1*b1) * w
     * </pre>
     */
    public Fp12Element mul(Fp12Element other)
    {
        // Lazy reduction: the three Fp^6 products stay unreduced and the six
        // output Fp^2 coefficients are reduced once each (12 Fp reductions
        // instead of 18).
        Fp2Wide[] a0b0 = c0.mulWide(other.c0);
        Fp2Wide[] a1b1 = c1.mulWide(other.c1);
        Fp2Wide[] t = Fp6Element.sub(Fp6Element.sub(c0.add(c1).mulWide(other.c0.add(other.c1)), a0b0), a1b1);
        Fp2Wide[] new0 = Fp6Element.add(a0b0, Fp6Element.mulByV(a1b1));
        return new Fp12Element(Fp6Element.reduce(new0), Fp6Element.reduce(t));
    }

    /**
     * Multiplies by the sparse element {@code (l0 + l1*v) + (l4*v)*w}, the shape
     * of a Miller-loop line evaluation (its non-zero coefficients sit at
     * positions 0, 1 and 4 of the Fp^2 basis {@code 1, v, v^2, w, vw, v^2w}).
     * Thirteen Fp^2 multiplications instead of eighteen, reduced lazily: one
     * reduction per output Fp coefficient.
     */
    Fp12Element mulBy014(Fp2Element l0, Fp2Element l1, Fp2Element l4)
    {
        Fp2Wide[] t0 = c0.mulBy01Wide(l0, l1);
        Fp2Wide[] t1 = c1.mulBy1Wide(l4);
        Fp2Wide[] t = Fp6Element.sub(Fp6Element.sub(c0.add(c1).mulBy01Wide(l0, l1.add(l4)), t0), t1);
        return new Fp12Element(Fp6Element.reduce(Fp6Element.add(t0, Fp6Element.mulByV(t1))), Fp6Element.reduce(t));
    }

    /**
     * Squaring for elements of the cyclotomic subgroup {@code G_Phi6(p^2)}
     * (where every value of the final exponentiation's hard part lives), by
     * Granger and Scott, "Faster Squaring in the Cyclotomic Subgroup of Sixth
     * Degree Extensions" (PKC 2010): viewing the element as three Fp^4 values,
     * nine Fp^2 squarings instead of the eighteen Fp^2 multiplications of
     * {@link #square()}. The result is wrong for elements outside that subgroup.
     */
    Fp12Element cyclotomicSquare()
    {
        Fp2Element z0 = c0.c0(), z4 = c0.c1(), z3 = c0.c2();
        Fp2Element z2 = c1.c0(), z1 = c1.c1(), z5 = c1.c2();

        Fp2Element[] a = fp4Square(z0, z1);
        Fp2Element[] b = fp4Square(z2, z3);
        Fp2Element[] c = fp4Square(z4, z5);

        // z = 3 * t - 2 * z (for the "real" halves) or 3 * t + 2 * z (for the "imaginary" halves).
        z0 = triplePlusTwice(a[0], z0.neg());
        z1 = triplePlusTwice(a[1], z1);
        z4 = triplePlusTwice(b[0], z4.neg());
        z5 = triplePlusTwice(b[1], z5);
        z2 = triplePlusTwice(c[1].mulByNonResidue(), z2);
        z3 = triplePlusTwice(c[0], z3.neg());

        return new Fp12Element(Fp6Element.of(z0, z4, z3), Fp6Element.of(z2, z1, z5));
    }

    /** {@code 3t + 2z}. */
    private static Fp2Element triplePlusTwice(Fp2Element t, Fp2Element z)
    {
        Fp2Element s = t.add(z);
        return s.add(s).add(t);
    }

    /**
     * Squares {@code a + b*s} in {@code Fp^4 = Fp^2[s] / (s^2 - xi)}, xi = 1 + I:
     * {@code (a^2 + xi*b^2) + ((a + b)^2 - a^2 - b^2) * s}, three Fp^2 squarings.
     */
    private static Fp2Element[] fp4Square(Fp2Element a, Fp2Element b)
    {
        Fp2Wide t0 = Fp2Wide.square(a);
        Fp2Wide t1 = Fp2Wide.square(b);
        Fp2Element c0 = t1.mulByNonResidue().add(t0).reduce();
        Fp2Element c1 = Fp2Wide.square(a.add(b)).sub(t0).sub(t1).reduce();
        return new Fp2Element[]{ c0, c1 };
    }

    /**
     * {@code this^e} for {@code this} in the cyclotomic subgroup and
     * {@code e >= 0}, left to right with {@link #cyclotomicSquare()} over the
     * width-4 NAF of {@code e}: its digits are 0 or odd in {@code [-7, 7]},
     * with at most one non-zero digit in any four consecutive ones. A
     * negative digit multiplies by the conjugate of the precomputed odd power,
     * which in the cyclotomic subgroup is its inverse. For the hard part's
     * 63-bit {@code (|x| + 1) / 3} (28 set bits, the alternating pattern of
     * {@code 0x5555} that a plain NAF cannot thin) this takes 16 Fp^12
     * multiplications, precomputation included, instead of 27.
     */
    Fp12Element cyclotomicPow(BigInteger e)
    {
        byte[] digits = WNafUtil.generateWindowNaf(4, e);
        if (digits.length == 0)
        {
            return ONE;
        }
        int maxDigit = 0;
        for (int i = 0; i < digits.length; ++i)
        {
            maxDigit = Math.max(maxDigit, Math.abs(digits[i]));
        }
        // odd[j] = this^(2j + 1), as far as the digits need.
        Fp12Element[] odd = new Fp12Element[(maxDigit + 1) / 2];
        odd[0] = this;
        if (odd.length > 1)
        {
            Fp12Element square = cyclotomicSquare();
            for (int j = 1; j < odd.length; ++j)
            {
                odd[j] = odd[j - 1].mul(square);
            }
        }
        // The most significant digit of a positive integer's NAF is positive.
        int top = digits.length - 1;
        Fp12Element result = odd[digits[top] >> 1];
        for (int i = top - 1; i >= 0; --i)
        {
            result = result.cyclotomicSquare();
            int d = digits[i];
            if (d > 0)
            {
                result = result.mul(odd[d >> 1]);
            }
            else if (d < 0)
            {
                result = result.mul(odd[-d >> 1].conjugate());
            }
        }
        return result;
    }

    /**
     * {@code this^e} for {@code this} in the cyclotomic subgroup and
     * {@code e >= 0}, by Karabina's compressed squaring ("Squaring in
     * cyclotomic subgroups", Math. Comp. 82, 2013; formulas as in Aranha,
     * Karabina, Longa, Gebotys and L&oacute;pez, "Faster explicit formulas for
     * computing pairings over ordinary curves", Eurocrypt 2011, sec. 5.2).
     * <p>
     * An element of the subgroup is determined by four of its six Fp^2
     * coefficients, {@code g2, g3, g4, g5} in the numbering of
     * {@link #cyclotomicSquare()}, and those four square among themselves in
     * six Fp^2 squarings instead of nine. This squares the compressed form
     * {@code bitLength(e) - 1} times, keeps {@code this^(2^i)} for each set
     * bit i of e, decompresses them together (one Fp^2 inversion for all of
     * them, by Montgomery's trick) and multiplies them. Decompression costs
     * about as much as a few squarings, so this pays for sparse exponents
     * such as |x| (six set bits in 64), not dense ones.
     * <p>
     * Decompression divides by {@code g2}; if any kept power has
     * {@code g2 = 0} (the identity does, any other element with probability
     * about {@code p^-2}) this falls back to {@link #cyclotomicPow}.
     */
    Fp12Element cyclotomicPowCompressed(BigInteger e)
    {
        int n = e.bitCount();
        Fp2Element[][] kept = new Fp2Element[n][];
        Fp2Element[] g = new Fp2Element[]{ c1.c0(), c0.c2(), c0.c1(), c1.c2() };
        int k = 0;
        for (int i = 0; i < e.bitLength(); ++i)
        {
            if (i > 0)
            {
                g = compressedSquare(g);
            }
            if (e.testBit(i))
            {
                kept[k++] = g;
            }
        }

        // Batch inversion of the denominators 4 * g2 (Montgomery's trick).
        Fp2Element[] prefix = new Fp2Element[n];
        Fp2Element acc = Fp2Element.ONE;
        for (int j = 0; j < n; ++j)
        {
            Fp2Element g2 = kept[j][0];
            if (g2.isZero())
            {
                return cyclotomicPow(e);
            }
            Fp2Element d = g2.add(g2);
            acc = acc.mul(d.add(d));
            prefix[j] = acc;
        }
        Fp2Element inv = acc.inverse();

        Fp12Element result = ONE;
        for (int j = n - 1; j >= 0; --j)
        {
            Fp2Element g2 = kept[j][0];
            Fp2Element dInv = j == 0 ? inv : inv.mul(prefix[j - 1]);
            if (j > 0)
            {
                Fp2Element d = g2.add(g2);
                inv = inv.mul(d.add(d));
            }
            Fp12Element power = decompress(kept[j], dInv);
            result = j == n - 1 ? power : result.mul(power);
        }
        return result;
    }

    /**
     * Karabina's squaring of a compressed element {@code [g2, g3, g4, g5]}:
     * <pre>
     *   h2 = 2 g2 + 3 xi (2 g4 g5)        h3 = 3 (g4^2 + xi g5^2) - 2 g3
     *   h4 = 3 (g2^2 + xi g3^2) - 2 g4    h5 = 2 g5 + 3 (2 g2 g3)
     * </pre>
     * with {@code 2 gi gj = (gi + gj)^2 - gi^2 - gj^2}: six Fp^2 squarings,
     * reduced once per output coefficient.
     */
    private static Fp2Element[] compressedSquare(Fp2Element[] g)
    {
        Fp2Element g2 = g[0], g3 = g[1], g4 = g[2], g5 = g[3];
        Fp2Wide s2 = Fp2Wide.square(g2);
        Fp2Wide s3 = Fp2Wide.square(g3);
        Fp2Wide s4 = Fp2Wide.square(g4);
        Fp2Wide s5 = Fp2Wide.square(g5);
        Fp2Element t45 = s5.mulByNonResidue().add(s4).reduce();
        Fp2Element t23 = s3.mulByNonResidue().add(s2).reduce();
        Fp2Element m45 = Fp2Wide.square(g4.add(g5)).sub(s4).sub(s5).reduce();
        Fp2Element m23 = Fp2Wide.square(g2.add(g3)).sub(s2).sub(s3).reduce();
        return new Fp2Element[]{ triplePlusTwice(m45.mulByNonResidue(), g2), triplePlusTwice(t45, g3.neg()),
            triplePlusTwice(t23, g4.neg()), triplePlusTwice(m23, g5) };
    }

    /**
     * Recovers the full element from {@code [g2, g3, g4, g5]} given
     * {@code dInv = (4 g2)^-1}:
     * <pre>
     *   g1 = (xi g5^2 + 3 g4^2 - 2 g3) / (4 g2)
     *   g0 = xi (2 g1^2 + g2 g5 - 3 g3 g4) + 1
     * </pre>
     */
    private static Fp12Element decompress(Fp2Element[] g, Fp2Element dInv)
    {
        Fp2Element g2 = g[0], g3 = g[1], g4 = g[2], g5 = g[3];
        Fp2Wide s4 = Fp2Wide.square(g4);
        Fp2Wide num = s4.add(s4).add(s4).add(Fp2Wide.square(g5).mulByNonResidue());
        Fp2Element g1 = num.reduce().sub(g3.add(g3)).mul(dInv);
        Fp2Wide s1 = Fp2Wide.square(g1);
        Fp2Wide p34 = Fp2Wide.mul(g3, g4);
        Fp2Element g0 = s1.add(s1).add(Fp2Wide.mul(g2, g5)).sub(p34.add(p34).add(p34)).mulByNonResidue().reduce()
            .add(Fp2Element.ONE);
        return new Fp12Element(Fp6Element.of(g0, g4, g3), Fp6Element.of(g2, g1, g5));
    }

    /**
     * Squaring via complex-style: (a0 + a1*w)^2 = (a0+a1)(a0+a1*v) - a0*a1 - a0*a1*v + 2*a0*a1*w.
     * Three Fp^6 multiplications versus four for the Karatsuba product.
     */
    public Fp12Element square()
    {
        Fp6Element ab = c0.mul(c1);
        Fp6Element c0PlusC1 = c0.add(c1);
        Fp6Element c0PlusVc1 = c0.add(c1.mulByV());
        Fp6Element new0 = c0PlusC1.mul(c0PlusVc1).sub(ab).sub(ab.mulByV());
        Fp6Element new1 = ab.add(ab);
        return new Fp12Element(new0, new1);
    }

    /**
     * Frobenius&sup2;: raise to the {@code p^2} power. Combines
     * {@link Fp6Element#frobeniusSquared()} on each Fp&sup6; component
     * with a multiplication by the precomputed Fp&sup2; coefficient
     * for the {@code w} basis on the c1 component.
     */
    public Fp12Element frobeniusSquared()
    {
        return new Fp12Element(c0.frobeniusSquared(), c1.frobeniusSquared().mulFp2(FROB_SQ_W));
    }

    /**
     * Frobenius: raise to the {@code p} power. Combines
     * {@link Fp6Element#frobenius()} on each Fp&sup6; component with a
     * multiplication by the precomputed Fp&sup2; coefficient for the
     * {@code w} basis on the c1 component.
     */
    public Fp12Element frobenius()
    {
        return new Fp12Element(c0.frobenius(), c1.frobenius().mulFp2(FROB_W));
    }

    /**
     * Conjugate: (c0 + c1*w) → (c0 - c1*w). For BLS12-381 this equals the
     * Fp^12 Frobenius applied 6 times (i.e. raising to the p^6 power), since
     * the cyclotomic structure makes p^6-Frobenius act as conjugation.
     */
    public Fp12Element conjugate()
    {
        return new Fp12Element(c0, c1.neg());
    }

    /**
     * Modular inverse:
     * <pre>
     *   (c0 + c1*w)^-1 = (c0 - c1*w) / (c0^2 - c1^2 * v)
     * </pre>
     */
    public Fp12Element inverse()
    {
        if (isZero())
        {
            throw new ArithmeticException("Fp12Element zero is not invertible");
        }
        Fp6Element norm = c0.square().sub(c1.square().mulByV());
        Fp6Element normInv = norm.inverse();
        return new Fp12Element(c0.mul(normInv), c1.neg().mul(normInv));
    }

    /**
     * Modular exponentiation by an integer exponent. Uses right-to-left
     * square-and-multiply on the bit representation of {@code exponent};
     * a negative exponent is handled by inverting and recursing on the
     * absolute value.
     */
    public Fp12Element modPow(BigInteger exponent)
    {
        if (exponent.signum() < 0)
        {
            return inverse().modPow(exponent.negate());
        }
        Fp12Element result = ONE;
        Fp12Element base = this;
        for (int i = 0; i < exponent.bitLength(); ++i)
        {
            if (exponent.testBit(i))
            {
                result = result.mul(base);
            }
            base = base.square();
        }
        return result;
    }

    public boolean equals(Object other)
    {
        if (!(other instanceof Fp12Element))
        {
            return false;
        }
        Fp12Element o = (Fp12Element)other;
        return c0.equals(o.c0) && c1.equals(o.c1);
    }

    public int hashCode()
    {
        return c0.hashCode() * 31 + c1.hashCode();
    }

    public String toString()
    {
        return "Fp12{" + c0 + ", " + c1 + "}";
    }
}
