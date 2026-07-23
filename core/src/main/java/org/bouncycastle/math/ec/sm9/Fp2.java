package org.bouncycastle.math.ec.sm9;

import java.math.BigInteger;

/**
 * Element of F_p2 = F_p[u]/(u^2 + 2), i.e. u^2 = -2, for the SM9 256-bit BN curve
 * (GM/T 0044.5-2016). Written a + b*u with a the low (constant) and b the high
 * (u-coefficient) dimension. Immutable.
 */
class Fp2
{
    // SM9 base field prime q (GM/T 0044.5-2016, clause 1).
    static final BigInteger Q = new BigInteger(
        "B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D", 16);

    static final Fp2 ZERO = new Fp2(BigInteger.ZERO, BigInteger.ZERO);
    static final Fp2 ONE = new Fp2(BigInteger.ONE, BigInteger.ZERO);

    final BigInteger a; // constant term
    final BigInteger b; // u coefficient

    Fp2(BigInteger a, BigInteger b)
    {
        this.a = a.mod(Q);
        this.b = b.mod(Q);
    }

    boolean isZero()
    {
        return a.signum() == 0 && b.signum() == 0;
    }

    Fp2 add(Fp2 o)
    {
        return new Fp2(a.add(o.a), b.add(o.b));
    }

    Fp2 subtract(Fp2 o)
    {
        return new Fp2(a.subtract(o.a), b.subtract(o.b));
    }

    Fp2 negate()
    {
        return new Fp2(a.negate(), b.negate());
    }

    Fp2 multiply(Fp2 o)
    {
        // (a + b u)(c + d u) = (ac - 2bd) + ((a+b)(c+d) - ac - bd) u
        BigInteger ac = a.multiply(o.a);
        BigInteger bd = b.multiply(o.b);
        BigInteger mid = a.add(b).multiply(o.a.add(o.b)).subtract(ac).subtract(bd);
        return new Fp2(ac.subtract(bd.shiftLeft(1)), mid);
    }

    Fp2 square()
    {
        return multiply(this);
    }

    /**
     * Multiply by u (u^2 = -2): (a + b u) * u = -2b + a u.
     */
    Fp2 mulU()
    {
        return new Fp2(b.shiftLeft(1).negate(), a);
    }

//    Fp2 mulScalar(BigInteger k)
//    {
//        return new Fp2(a.multiply(k), b.multiply(k));
//    }

    Fp2 invert()
    {
        // norm = a^2 - (u^2) b^2 = a^2 + 2 b^2
        BigInteger norm = a.multiply(a).add(b.multiply(b).shiftLeft(1)).mod(Q);
        BigInteger ni = norm.modInverse(Q);
        return new Fp2(a.multiply(ni), b.negate().multiply(ni));
    }

    /**
     * Frobenius x -> x^p on F_p2, which negates the u coefficient (conjugation).
     */
//    Fp2 conjugate()
//    {
//        return new Fp2(a, b.negate());
//    }

    public boolean equals(Object other)
    {
        if (this == other)
        {
            return true;
        }
        if (!(other instanceof Fp2))
        {
            return false;
        }
        Fp2 o = (Fp2)other;
        return a.equals(o.a) && b.equals(o.b);
    }

    public int hashCode()
    {
        return a.hashCode() ^ (b.hashCode() * 31);
    }
}
