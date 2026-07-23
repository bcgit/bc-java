package org.bouncycastle.math.ec.sm9;

import java.math.BigInteger;

/**
 * Element of F_p12 = F_p4[w]/(w^3 - v), i.e. w^3 = v, for SM9 (GM/T 0044.5-2016,
 * 1-2-4-12 tower). This is the pairing target group G_T. Written a + b*w + c*w^2
 * with a the low and c the high (w^2-coefficient) dimension, a, b, c in
 * {@link Fp4}. Immutable.
 */
public class Fp12
{
//    static final Fp12 ZERO = new Fp12(Fp4.ZERO, Fp4.ZERO, Fp4.ZERO);
    static final Fp12 ONE = new Fp12(Fp4.ONE, Fp4.ZERO, Fp4.ZERO);
    static final Fp12 W = new Fp12(Fp4.ZERO, Fp4.ONE, Fp4.ZERO);

    final Fp4 a; // constant term
    final Fp4 b; // w coefficient
    final Fp4 c; // w^2 coefficient

    Fp12(Fp4 a, Fp4 b, Fp4 c)
    {
        this.a = a;
        this.b = b;
        this.c = c;
    }

//    boolean isZero()
//    {
//        return a.isZero() && b.isZero() && c.isZero();
//    }

    Fp12 add(Fp12 o)
    {
        return new Fp12(a.add(o.a), b.add(o.b), c.add(o.c));
    }

    Fp12 subtract(Fp12 o)
    {
        return new Fp12(a.subtract(o.a), b.subtract(o.b), c.subtract(o.c));
    }

    Fp12 negate()
    {
        return new Fp12(a.negate(), b.negate(), c.negate());
    }

    public Fp12 multiply(Fp12 o)
    {
        // schoolbook in w with reduction w^3 = v, w^4 = v*w
        Fp4 a0 = a, a1 = b, a2 = c;
        Fp4 b0 = o.a, b1 = o.b, b2 = o.c;
        Fp4 p0 = a0.multiply(b0);
        Fp4 p1 = a0.multiply(b1).add(a1.multiply(b0));
        Fp4 p2 = a0.multiply(b2).add(a1.multiply(b1)).add(a2.multiply(b0));
        Fp4 p3 = a1.multiply(b2).add(a2.multiply(b1));
        Fp4 p4 = a2.multiply(b2);
        return new Fp12(p0.add(p3.mulV()), p1.add(p4.mulV()), p2);
    }

    Fp12 square()
    {
        return multiply(this);
    }

    Fp12 invert()
    {
        // cubic extension inverse, L = F_p4[w]/(w^3 - gamma), gamma = v:
        //   t0 = a^2 - gamma*b*c ; t1 = gamma*c^2 - a*b ; t2 = b^2 - a*c
        //   norm = a*t0 + gamma*(b*t2 + c*t1) ;  inv = (t0 + t1 w + t2 w^2)/norm
        Fp4 t0 = a.square().subtract(b.multiply(c).mulV());
        Fp4 t1 = c.square().mulV().subtract(a.multiply(b));
        Fp4 t2 = b.square().subtract(a.multiply(c));
        Fp4 norm = a.multiply(t0).add(b.multiply(t2).add(c.multiply(t1)).mulV());
        Fp4 ni = norm.invert();
        return new Fp12(t0.multiply(ni), t1.multiply(ni), t2.multiply(ni));
    }

    /**
     * Variable-time exponentiation, for PUBLIC exponents only (the pairing's
     * Frobenius and final exponentiation, and g^h' in signature verification).
     * For secret exponents use {@link #powSecure}.
     */
    public Fp12 pow(BigInteger e)
    {
        Fp12 r = ONE;
        Fp12 b = this;
        int n = e.bitLength();
        for (int i = 0; i < n; ++i)
        {
            if (e.testBit(i))
            {
                r = r.multiply(b);
            }
            b = b.square();
        }
        return r;
    }

    /**
     * Constant-pattern exponentiation for SECRET exponents (a Montgomery ladder
     * running a fixed number of iterations - the SM9 group order bit length - with
     * exactly one multiply and one square per bit regardless of the exponent bits),
     * used for w = g^r where r is a signing nonce or ephemeral secret. Unlike
     * {@link #pow}, the operation pattern does not leak the exponent's Hamming
     * weight or individual bits. The exponent must satisfy 0 &lt;= e &lt; N (every
     * SM9 secret exponent is reduced mod the group order N).
     * <p>
     * NOTE: the underlying F_p arithmetic is BigInteger-based and is not itself
     * constant time, so this removes the exponent-structure leak but not every
     * timing side channel.
     */
    public Fp12 powSecure(BigInteger e)
    {
        Fp12 r0 = ONE;
        Fp12 r1 = this;
        for (int i = SM9Curve.N.bitLength() - 1; i >= 0; --i)
        {
            if (e.testBit(i))
            {
                r0 = r0.multiply(r1);   // bit 1: (r0, r1) <- (r0*r1, r1^2)
                r1 = r1.multiply(r1);
            }
            else
            {
                r1 = r0.multiply(r1);   // bit 0: (r0, r1) <- (r0^2, r0*r1)
                r0 = r0.multiply(r0);
            }
        }
        return r0;
    }

    public boolean equals(Object other)
    {
        if (this == other)
        {
            return true;
        }
        if (!(other instanceof Fp12))
        {
            return false;
        }
        Fp12 o = (Fp12)other;
        return a.equals(o.a) && b.equals(o.b) && c.equals(o.c);
    }

    public int hashCode()
    {
        return a.hashCode() ^ (b.hashCode() * 31) ^ (c.hashCode() * 961);
    }
}
