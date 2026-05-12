package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

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
        Fp6Element a0b0 = c0.mul(other.c0);
        Fp6Element a1b1 = c1.mul(other.c1);
        Fp6Element t = c0.add(c1).mul(other.c0.add(other.c1)).sub(a0b0).sub(a1b1);
        Fp6Element new0 = a0b0.add(a1b1.mulByV());
        return new Fp12Element(new0, t);
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
