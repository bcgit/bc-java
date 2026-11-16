package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

import org.bouncycastle.util.Arrays;

/**
 * Immutable element of {@code Fp^2 = Fp[I] / (I^2 + 1)}, used as the base
 * field of BLS12-381 G2.
 * <p>
 * The two Fp components are held as {@code Fp} elements, c0 then c1, in one
 * int array: twelve limbs each, in Montgomery form, fully reduced. Addition,
 * subtraction, multiplication and squaring are constant time, and so is the
 * inversion of the norm in {@link #inverse()}; {@link #c0()} and
 * {@link #c1()} convert to {@link BigInteger} on demand.
 */
public final class Fp2Element
{
    /** Field characteristic, identical to the BLS12-381 base field p. */
    public static final BigInteger P = BLS12_381G1.Q;

    private static final int S = Fp.SIZE;

    /** The Fp^2 zero element. */
    public static final Fp2Element ZERO = new Fp2Element(new int[2 * S]);

    /** The Fp^2 one element (1 + 0*I). */
    public static final Fp2Element ONE;

    static
    {
        int[] one = new int[2 * S];
        System.arraycopy(Fp.ONE, 0, one, 0, S);
        ONE = new Fp2Element(one);
    }

    /** c0 at 0, c1 at {@link Fp#SIZE}; never modified once the element is built. */
    final int[] v;

    Fp2Element(int[] v)
    {
        this.v = v;
    }

    public static Fp2Element of(BigInteger c0, BigInteger c1)
    {
        int[] v = new int[2 * S];
        Fp.fromBigInteger(c0, v, 0);
        Fp.fromBigInteger(c1, v, S);
        return new Fp2Element(v);
    }

    public static Fp2Element of(long c0, long c1)
    {
        return of(BigInteger.valueOf(c0), BigInteger.valueOf(c1));
    }

    public static Fp2Element fromFp(BigInteger c0)
    {
        return of(c0, BigInteger.ZERO);
    }

    /**
     * @return real component (the c0 in c0 + c1*I).
     */
    public BigInteger c0()
    {
        return Fp.toBigInteger(v, 0);
    }

    /**
     * @return imaginary component (the c1 in c0 + c1*I).
     */
    public BigInteger c1()
    {
        return Fp.toBigInteger(v, S);
    }

    public boolean isZero()
    {
        return Fp.isZero(v, 0) & Fp.isZero(v, S);
    }

    public Fp2Element add(Fp2Element other)
    {
        int[] z = new int[2 * S];
        Fp.add(v, 0, other.v, 0, z, 0);
        Fp.add(v, S, other.v, S, z, S);
        return new Fp2Element(z);
    }

    public Fp2Element sub(Fp2Element other)
    {
        int[] z = new int[2 * S];
        Fp.sub(v, 0, other.v, 0, z, 0);
        Fp.sub(v, S, other.v, S, z, S);
        return new Fp2Element(z);
    }

    public Fp2Element neg()
    {
        int[] z = new int[2 * S];
        Fp.neg(v, 0, z, 0);
        Fp.neg(v, S, z, S);
        return new Fp2Element(z);
    }

    /**
     * (a + b*I)(c + d*I) = (ac - bd) + (ad + bc)*I, with Karatsuba's
     * {@code ad + bc = (a + b)(c + d) - ac - bd}: three Fp products, formed in
     * full and reduced once per component.
     */
    public Fp2Element mul(Fp2Element other)
    {
        return Fp2Wide.mul(this, other).reduce();
    }

    /**
     * Multiply by {@code 1 + I}, the cubic non-residue defining Fp^6:
     * (a + b*I)(1 + I) = (a - b) + (a + b)*I, with no Fp multiplication.
     */
    Fp2Element mulByNonResidue()
    {
        int[] z = new int[2 * S];
        Fp.sub(v, 0, v, S, z, 0);
        Fp.add(v, 0, v, S, z, S);
        return new Fp2Element(z);
    }

    /**
     * Multiply by a Fp scalar.
     */
    public Fp2Element mulFp(BigInteger fp)
    {
        int[] s = new int[S];
        Fp.fromBigInteger(fp, s, 0);
        return mulFp(s);
    }

    /**
     * Multiply by the Fp element s, in the form of {@link Fp}.
     */
    Fp2Element mulFp(int[] s)
    {
        int[] z = new int[2 * S];
        Fp.mul(v, 0, s, 0, z, 0);
        Fp.mul(v, S, s, 0, z, S);
        return new Fp2Element(z);
    }

    /**
     * (a + b*I)^2 = (a-b)(a+b) + 2ab*I: two Fp products.
     */
    public Fp2Element square()
    {
        int[] t = new int[2 * S];
        Fp.add(v, 0, v, S, t, 0);
        Fp.sub(v, 0, v, S, t, S);
        int[] z = new int[2 * S];
        Fp.mul(t, 0, t, S, z, 0);
        Fp.mul(v, 0, v, S, z, S);
        Fp.add(z, S, z, S, z, S);
        return new Fp2Element(z);
    }

    /**
     * Frobenius: (c0 + c1*I)^p = c0 - c1*I when p &equiv; 3 (mod 4),
     * which holds for the BLS12-381 base field.
     */
    public Fp2Element frobenius()
    {
        return conjugate();
    }

    private Fp2Element conjugate()
    {
        int[] z = new int[2 * S];
        System.arraycopy(v, 0, z, 0, S);
        Fp.neg(v, S, z, S);
        return new Fp2Element(z);
    }

    /**
     * Multiply by I: (c0 + c1*I) * I = -c1 + c0*I.
     */
    private Fp2Element mulByI()
    {
        int[] z = new int[2 * S];
        Fp.neg(v, S, z, 0);
        System.arraycopy(v, 0, z, S, S);
        return new Fp2Element(z);
    }

    /**
     * Modular inverse: (c0 + c1*I)^-1 = (c0 - c1*I) / (c0^2 + c1^2), with the
     * norm inverted by the constant-time {@code Fp.inv}.
     */
    public Fp2Element inverse()
    {
        if (isZero())
        {
            throw new ArithmeticException("Fp2Element zero is not invertible");
        }
        int[] tt = new int[2 * Fp.WIDE];
        Fp.sqrWide(v, 0, tt, 0);
        Fp.sqrWide(v, S, tt, Fp.WIDE);
        Fp.addWide(tt, 0, tt, Fp.WIDE, tt, 0);
        int[] norm = new int[S];
        Fp.reduceWide(tt, 0, norm, 0);
        Fp.inv(norm, 0, norm, 0);
        return conjugate().mulFp(norm);
    }

    /**
     * Modular exponentiation in Fp^2 by a non-negative integer exponent.
     */
    public Fp2Element modPow(BigInteger exponent)
    {
        if (exponent.signum() < 0)
        {
            throw new IllegalArgumentException("negative exponent");
        }
        Fp2Element result = ONE;
        Fp2Element base = this;
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

    /**
     * RFC 9380 sec. 4.1 sgn0 for m = 2.
     * <pre>
     *   sign_0 = c0 mod 2
     *   zero_0 = (c0 == 0)
     *   sign_1 = c1 mod 2
     *   return sign_0 OR (zero_0 AND sign_1)
     * </pre>
     */
    public int sgn0()
    {
        int[] t = new int[2 * S];
        Fp.fromMont(v, 0, t, 0);
        Fp.fromMont(v, S, t, S);
        int sign0 = t[0] & 1;
        int zero0 = Fp.isZero(v, 0) ? 1 : 0;
        int sign1 = t[S] & 1;
        return sign0 | (zero0 & sign1);
    }

    /**
     * Tries to compute a square root of {@code this} in Fp^2, using the
     * Wahby-Boneh algorithm specialised to p &equiv; 3 (mod 4)
     * ("Fast and simple constant-time hashing to the BLS12-381 elliptic
     * curve", Algorithm 1).
     *
     * @return a square root, or {@code null} if {@code this} is not a square.
     */
    public Fp2Element sqrtOrNull()
    {
        if (isZero())
        {
            return ZERO;
        }
        // a1 = a^((p - 3) / 4)
        BigInteger pMinus3Over4 = P.subtract(BigInteger.valueOf(3)).shiftRight(2);
        Fp2Element a1 = modPow(pMinus3Over4);
        Fp2Element alpha = a1.square().mul(this);
        // a0 = alpha^p * alpha = (Frobenius(alpha)) * alpha = norm of alpha in Fp.
        Fp2Element a0 = alpha.frobenius().mul(alpha);
        Fp2Element minusOne = ONE.neg();
        if (a0.equals(minusOne))
        {
            return null;
        }
        Fp2Element x0 = a1.mul(this);
        if (alpha.equals(minusOne))
        {
            return x0.mulByI();
        }
        BigInteger pMinus1Over2 = P.subtract(BigInteger.ONE).shiftRight(1);
        Fp2Element b = ONE.add(alpha).modPow(pMinus1Over2);
        return b.mul(x0);
    }

    public boolean isSquare()
    {
        // a is a square in Fp^2 iff a^((p^2 - 1) / 2) = 1.
        BigInteger qMinus1Over2 = P.multiply(P).subtract(BigInteger.ONE).shiftRight(1);
        return modPow(qMinus1Over2).equals(ONE);
    }

    /**
     * Each element has one form, so equal elements have equal limbs.
     */
    public boolean equals(Object other)
    {
        if (!(other instanceof Fp2Element))
        {
            return false;
        }
        Fp2Element o = (Fp2Element)other;
        return Fp.eq(v, 0, o.v, 0) & Fp.eq(v, S, o.v, S);
    }

    public int hashCode()
    {
        return Arrays.hashCode(v);
    }

    public String toString()
    {
        return "(" + c0().toString(16) + " + " + c1().toString(16) + " * I)";
    }
}
