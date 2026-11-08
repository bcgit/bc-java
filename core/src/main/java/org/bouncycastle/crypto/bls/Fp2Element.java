package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

/**
 * Immutable element of {@code Fp^2 = Fp[I] / (I^2 + 1)}, used as the base
 * field of BLS12-381 G2.
 * <p>
 * All operations reduce modulo p eagerly. Internally the two Fp components
 * are stored as plain {@link BigInteger} values in {@code [0, p)}. Sums and
 * differences are brought back into range with one conditional subtraction or
 * addition, and products with a Barrett reduction rather than
 * {@link BigInteger#mod}, whose long division costs several multiplications.
 */
public final class Fp2Element
{
    /** Field characteristic, identical to the BLS12-381 base field p. */
    public static final BigInteger P = BLS12_381G1.Q;

    /** Bit length of p. */
    private static final int K = P.bitLength();

    /** Barrett exponent: {@link #reduce} accepts inputs below {@code 2^BARRETT_BITS}. */
    private static final int BARRETT_BITS = 2 * K + 2;

    /** Barrett constant {@code floor(2^BARRETT_BITS / p)}. */
    private static final BigInteger MU = BigInteger.ONE.shiftLeft(BARRETT_BITS).divide(P);

    /** p^2, added to bring a negative difference of two products into range. */
    private static final BigInteger P_SQUARED = P.multiply(P);

    /** The Fp^2 zero element. */
    public static final Fp2Element ZERO = new Fp2Element(BigInteger.ZERO, BigInteger.ZERO);

    /** The Fp^2 one element (1 + 0*I). */
    public static final Fp2Element ONE = new Fp2Element(BigInteger.ONE, BigInteger.ZERO);

    private final BigInteger c0;
    private final BigInteger c1;

    private Fp2Element(BigInteger c0, BigInteger c1)
    {
        this.c0 = c0;
        this.c1 = c1;
    }

    public static Fp2Element of(BigInteger c0, BigInteger c1)
    {
        return new Fp2Element(c0.mod(P), c1.mod(P));
    }

    /** Wraps components already in {@code [0, p)}, without reducing them. */
    static Fp2Element ofReduced(BigInteger c0, BigInteger c1)
    {
        return new Fp2Element(c0, c1);
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
        return c0;
    }

    /**
     * @return imaginary component (the c1 in c0 + c1*I).
     */
    public BigInteger c1()
    {
        return c1;
    }

    public boolean isZero()
    {
        return c0.signum() == 0 && c1.signum() == 0;
    }

    public Fp2Element add(Fp2Element other)
    {
        return new Fp2Element(addFp(c0, other.c0), addFp(c1, other.c1));
    }

    public Fp2Element sub(Fp2Element other)
    {
        return new Fp2Element(subFp(c0, other.c0), subFp(c1, other.c1));
    }

    public Fp2Element neg()
    {
        return new Fp2Element(negFp(c0), negFp(c1));
    }

    /**
     * (a + b*I)(c + d*I) = (ac - bd) + (ad + bc)*I, with Karatsuba's
     * {@code ad + bc = (a + b)(c + d) - ac - bd}: three Fp multiplications
     * instead of four.
     */
    public Fp2Element mul(Fp2Element other)
    {
        BigInteger ac = c0.multiply(other.c0);
        BigInteger bd = c1.multiply(other.c1);
        BigInteger sum = c0.add(c1).multiply(other.c0.add(other.c1));
        return new Fp2Element(reduceSigned(ac.subtract(bd)), reduce(sum.subtract(ac).subtract(bd)));
    }

    /**
     * Multiply by {@code 1 + I}, the cubic non-residue defining Fp^6:
     * (a + b*I)(1 + I) = (a - b) + (a + b)*I, with no Fp multiplication.
     */
    Fp2Element mulByNonResidue()
    {
        return new Fp2Element(subFp(c0, c1), addFp(c0, c1));
    }

    /**
     * Multiply by a Fp scalar.
     */
    public Fp2Element mulFp(BigInteger fp)
    {
        BigInteger r = fp.mod(P);
        return new Fp2Element(reduce(c0.multiply(r)), reduce(c1.multiply(r)));
    }

    /**
     * (a + b*I)^2 = (a-b)(a+b) + 2ab*I.
     */
    public Fp2Element square()
    {
        BigInteger sum = c0.add(c1);
        BigInteger diff = subFp(c0, c1);
        BigInteger newC0 = reduce(sum.multiply(diff));
        BigInteger newC1 = reduce(c0.multiply(c1).shiftLeft(1));
        return new Fp2Element(newC0, newC1);
    }

    /**
     * Frobenius: (c0 + c1*I)^p = c0 - c1*I when p &equiv; 3 (mod 4),
     * which holds for the BLS12-381 base field.
     */
    public Fp2Element frobenius()
    {
        return new Fp2Element(c0, negFp(c1));
    }

    /**
     * Modular inverse: (c0 + c1*I)^-1 = (c0 - c1*I) / (c0^2 + c1^2).
     */
    public Fp2Element inverse()
    {
        if (isZero())
        {
            throw new ArithmeticException("Fp2Element zero is not invertible");
        }
        BigInteger norm = reduce(c0.multiply(c0).add(c1.multiply(c1)));
        BigInteger normInv = norm.modInverse(P);
        return new Fp2Element(
            reduce(c0.multiply(normInv)),
            reduce(negFp(c1).multiply(normInv)));
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
        int sign0 = c0.testBit(0) ? 1 : 0;
        int zero0 = c0.signum() == 0 ? 1 : 0;
        int sign1 = c1.testBit(0) ? 1 : 0;
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
        if (a0.equals(ONE.neg()))
        {
            return null;
        }
        Fp2Element x0 = a1.mul(this);
        if (alpha.equals(ONE.neg()))
        {
            // multiply by I
            return new Fp2Element(negFp(x0.c1), x0.c0);
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

    /** {@code (a + b) mod p} for {@code a, b} in {@code [0, p)}. */
    static BigInteger addFp(BigInteger a, BigInteger b)
    {
        BigInteger s = a.add(b);
        return s.compareTo(P) >= 0 ? s.subtract(P) : s;
    }

    /** {@code (a - b) mod p} for {@code a, b} in {@code [0, p)}. */
    static BigInteger subFp(BigInteger a, BigInteger b)
    {
        BigInteger d = a.subtract(b);
        return d.signum() < 0 ? d.add(P) : d;
    }

    /** {@code -a mod p} for {@code a} in {@code [0, p)}. */
    static BigInteger negFp(BigInteger a)
    {
        return a.signum() == 0 ? a : P.subtract(a);
    }

    /**
     * {@code x mod p} for {@code 0 <= x < 2^BARRETT_BITS}, by Barrett reduction.
     * The quotient estimate {@code floor(floor(x / 2^(K-1)) * MU / 2^(BARRETT_BITS-K+1))}
     * never exceeds {@code floor(x / p)}, as every step rounds down, and falls
     * short of it by less than {@code x / 2^BARRETT_BITS + 2^(K-1) / p + 1}. Every
     * caller passes a sum of at most two products of reduced values,
     * {@code x < 2p^2}, where that is below 2, so one corrective subtraction is
     * the most that can follow; the loop is for completeness.
     */
    static BigInteger reduce(BigInteger x)
    {
        BigInteger q = x.shiftRight(K - 1).multiply(MU).shiftRight(BARRETT_BITS - K + 1);
        BigInteger r = x.subtract(q.multiply(P));
        while (r.compareTo(P) >= 0)
        {
            r = r.subtract(P);
        }
        return r;
    }

    /** {@code x mod p} for {@code -p^2 <= x < 2^BARRETT_BITS - p^2}. */
    private static BigInteger reduceSigned(BigInteger x)
    {
        return reduce(x.signum() < 0 ? x.add(P_SQUARED) : x);
    }

    public boolean equals(Object other)
    {
        if (!(other instanceof Fp2Element))
        {
            return false;
        }
        Fp2Element o = (Fp2Element)other;
        return c0.equals(o.c0) && c1.equals(o.c1);
    }

    public int hashCode()
    {
        return c0.hashCode() * 31 + c1.hashCode();
    }

    public String toString()
    {
        return "(" + c0.toString(16) + " + " + c1.toString(16) + " * I)";
    }
}
