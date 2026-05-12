package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

/**
 * Immutable element of {@code Fp^6 = Fp^2[v] / (v^3 - (1 + I))}, the cubic
 * extension of {@link Fp2Element} used as the inner level of the BLS12-381
 * pairing field tower.
 * <p>
 * An element is represented as {@code c0 + c1*v + c2*v^2} where each c_i is
 * an Fp^2 element. Multiplication uses the relation {@code v^3 = NON_RESIDUE}
 * where {@code NON_RESIDUE = 1 + I}, the standard BLS12-381 cubic non-residue
 * choice.
 */
public final class Fp6Element
{
    /** The cubic non-residue used to define Fp^6: NON_RESIDUE = 1 + I. */
    static final Fp2Element NON_RESIDUE = Fp2Element.of(1, 1);

    /**
     * Frobenius<sup>2</sup> coefficient for the {@code v} basis:
     * {@code (1 + I)^((p^2 - 1) / 3)} in Fp&sup2;. This is a primitive cube
     * root of unity; together with its square it provides the entire
     * Frobenius<sup>2</sup> action on Fp&sup6;.
     */
    private static final Fp2Element FROB_SQ_V;

    /** Square of {@link #FROB_SQ_V}, applied to the v&sup2; basis component. */
    private static final Fp2Element FROB_SQ_V2;

    /**
     * Frobenius coefficient for the {@code v} basis: {@code (1 + I)^((p - 1) / 3)}
     * in Fp&sup2;.
     */
    private static final Fp2Element FROB_V;

    /** Square of {@link #FROB_V}, applied to the v&sup2; basis component under Frobenius. */
    private static final Fp2Element FROB_V2;

    static
    {
        BigInteger pSqMinus1Over3 = Fp2Element.P.pow(2)
            .subtract(BigInteger.ONE)
            .divide(BigInteger.valueOf(3));
        FROB_SQ_V = NON_RESIDUE.modPow(pSqMinus1Over3);
        FROB_SQ_V2 = FROB_SQ_V.square();

        BigInteger pMinus1Over3 = Fp2Element.P
            .subtract(BigInteger.ONE)
            .divide(BigInteger.valueOf(3));
        FROB_V = NON_RESIDUE.modPow(pMinus1Over3);
        FROB_V2 = FROB_V.square();
    }

    public static final Fp6Element ZERO = new Fp6Element(Fp2Element.ZERO, Fp2Element.ZERO, Fp2Element.ZERO);
    public static final Fp6Element ONE = new Fp6Element(Fp2Element.ONE, Fp2Element.ZERO, Fp2Element.ZERO);

    private final Fp2Element c0;
    private final Fp2Element c1;
    private final Fp2Element c2;

    private Fp6Element(Fp2Element c0, Fp2Element c1, Fp2Element c2)
    {
        this.c0 = c0;
        this.c1 = c1;
        this.c2 = c2;
    }

    public static Fp6Element of(Fp2Element c0, Fp2Element c1, Fp2Element c2)
    {
        return new Fp6Element(c0, c1, c2);
    }

    public static Fp6Element fromFp2(Fp2Element c0)
    {
        return new Fp6Element(c0, Fp2Element.ZERO, Fp2Element.ZERO);
    }

    public Fp2Element c0()
    {
        return c0;
    }

    public Fp2Element c1()
    {
        return c1;
    }

    public Fp2Element c2()
    {
        return c2;
    }

    public boolean isZero()
    {
        return c0.isZero() && c1.isZero() && c2.isZero();
    }

    public Fp6Element add(Fp6Element other)
    {
        return new Fp6Element(c0.add(other.c0), c1.add(other.c1), c2.add(other.c2));
    }

    public Fp6Element sub(Fp6Element other)
    {
        return new Fp6Element(c0.sub(other.c0), c1.sub(other.c1), c2.sub(other.c2));
    }

    public Fp6Element neg()
    {
        return new Fp6Element(c0.neg(), c1.neg(), c2.neg());
    }

    /**
     * Schoolbook multiplication using {@code v^3 = NON_RESIDUE}:
     * <pre>
     *   (a0 + a1*v + a2*v^2) * (b0 + b1*v + b2*v^2)
     *   = (a0*b0 + (a1*b2 + a2*b1)*xi)
     *   + (a0*b1 + a1*b0 + a2*b2*xi) * v
     *   + (a0*b2 + a1*b1 + a2*b0) * v^2
     * </pre>
     * where xi = NON_RESIDUE.
     */
    public Fp6Element mul(Fp6Element other)
    {
        Fp2Element a0b0 = c0.mul(other.c0);
        Fp2Element a1b1 = c1.mul(other.c1);
        Fp2Element a2b2 = c2.mul(other.c2);

        Fp2Element t1 = c1.add(c2).mul(other.c1.add(other.c2)).sub(a1b1).sub(a2b2);
        Fp2Element t2 = c0.add(c1).mul(other.c0.add(other.c1)).sub(a0b0).sub(a1b1);
        Fp2Element t3 = c0.add(c2).mul(other.c0.add(other.c2)).sub(a0b0).sub(a2b2);

        Fp2Element new0 = a0b0.add(t1.mul(NON_RESIDUE));
        Fp2Element new1 = t2.add(a2b2.mul(NON_RESIDUE));
        Fp2Element new2 = t3.add(a1b1);

        return new Fp6Element(new0, new1, new2);
    }

    /**
     * Squaring via the Chung-Hasan SQR3 algorithm: 6 Fp^2 multiplications
     * versus 9 for the schoolbook product.
     */
    public Fp6Element square()
    {
        Fp2Element s0 = c0.square();
        Fp2Element ab = c0.mul(c1);
        Fp2Element s1 = ab.add(ab);
        Fp2Element s2 = c0.sub(c1).add(c2).square();
        Fp2Element bc = c1.mul(c2);
        Fp2Element s3 = bc.add(bc);
        Fp2Element s4 = c2.square();

        Fp2Element new0 = s0.add(s3.mul(NON_RESIDUE));
        Fp2Element new1 = s1.add(s4.mul(NON_RESIDUE));
        Fp2Element new2 = s1.add(s2).add(s3).sub(s0).sub(s4);

        return new Fp6Element(new0, new1, new2);
    }

    /**
     * Multiplies an element of Fp^6 by {@code v}, the polynomial generator.
     * Useful for the Fp^12 multiplication formula.
     */
    public Fp6Element mulByV()
    {
        // (c0 + c1*v + c2*v^2) * v = c0*v + c1*v^2 + c2*v^3
        //                          = c2 * NON_RESIDUE + c0 * v + c1 * v^2
        return new Fp6Element(c2.mul(NON_RESIDUE), c0, c1);
    }

    /**
     * Multiplies by an Fp^2 scalar.
     */
    public Fp6Element mulFp2(Fp2Element s)
    {
        return new Fp6Element(c0.mul(s), c1.mul(s), c2.mul(s));
    }

    /**
     * Inverse via the standard cubic-extension formula:
     * <pre>
     *   t0 = c0^2 - xi*c1*c2
     *   t1 = xi*c2^2 - c0*c1
     *   t2 = c1^2 - c0*c2
     *   norm = c0*t0 + xi*c2*t1 + xi*c1*t2
     *   inv = (t0 + t1*v + t2*v^2) / norm
     * </pre>
     */
    public Fp6Element inverse()
    {
        if (isZero())
        {
            throw new ArithmeticException("Fp6Element zero is not invertible");
        }
        Fp2Element t0 = c0.square().sub(c1.mul(c2).mul(NON_RESIDUE));
        Fp2Element t1 = c2.square().mul(NON_RESIDUE).sub(c0.mul(c1));
        Fp2Element t2 = c1.square().sub(c0.mul(c2));
        Fp2Element norm = c0.mul(t0).add(c2.mul(t1).mul(NON_RESIDUE)).add(c1.mul(t2).mul(NON_RESIDUE));
        Fp2Element normInv = norm.inverse();
        return new Fp6Element(t0.mul(normInv), t1.mul(normInv), t2.mul(normInv));
    }

    /**
     * Frobenius&sup2;: raise to the {@code p^2} power. Identity on Fp&sup2;
     * components (Frobenius&sup2; in Fp&sup2; is identity), with the
     * {@code v}-basis components scaled by precomputed Fp&sup2; constants.
     */
    public Fp6Element frobeniusSquared()
    {
        return new Fp6Element(c0, c1.mul(FROB_SQ_V), c2.mul(FROB_SQ_V2));
    }

    /**
     * Frobenius: raise to the {@code p} power. The Fp&sup2; components are
     * conjugated (Fp&sup2; Frobenius is conjugation since p &equiv; 3 mod 4),
     * then the v-basis components are scaled by precomputed coefficients.
     */
    public Fp6Element frobenius()
    {
        return new Fp6Element(
            c0.frobenius(),
            c1.frobenius().mul(FROB_V),
            c2.frobenius().mul(FROB_V2));
    }

    /**
     * Modular exponentiation by a non-negative integer.
     */
    public Fp6Element modPow(BigInteger exponent)
    {
        if (exponent.signum() < 0)
        {
            throw new IllegalArgumentException("negative exponent");
        }
        Fp6Element result = ONE;
        Fp6Element base = this;
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
        if (!(other instanceof Fp6Element))
        {
            return false;
        }
        Fp6Element o = (Fp6Element)other;
        return c0.equals(o.c0) && c1.equals(o.c1) && c2.equals(o.c2);
    }

    public int hashCode()
    {
        return (c0.hashCode() * 31 + c1.hashCode()) * 31 + c2.hashCode();
    }

    public String toString()
    {
        return "Fp6{" + c0 + ", " + c1 + ", " + c2 + "}";
    }
}
