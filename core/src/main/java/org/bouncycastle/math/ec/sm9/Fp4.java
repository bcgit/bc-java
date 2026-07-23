package org.bouncycastle.math.ec.sm9;

/**
 * Element of F_p4 = F_p2[v]/(v^2 - u), i.e. v^2 = u, for SM9 (GM/T 0044.5-2016,
 * 1-2-4-12 tower). Written a + b*v with a the low and b the high (v-coefficient)
 * dimension, a, b in {@link Fp2}. Immutable.
 */
class Fp4
{
    static final Fp4 ZERO = new Fp4(Fp2.ZERO, Fp2.ZERO);
    static final Fp4 ONE = new Fp4(Fp2.ONE, Fp2.ZERO);
//    static final Fp4 V = new Fp4(Fp2.ZERO, Fp2.ONE);

    final Fp2 a; // constant term
    final Fp2 b; // v coefficient

    Fp4(Fp2 a, Fp2 b)
    {
        this.a = a;
        this.b = b;
    }

//    boolean isZero()
//    {
//        return a.isZero() && b.isZero();
//    }

    Fp4 add(Fp4 o)
    {
        return new Fp4(a.add(o.a), b.add(o.b));
    }

    Fp4 subtract(Fp4 o)
    {
        return new Fp4(a.subtract(o.a), b.subtract(o.b));
    }

    Fp4 negate()
    {
        return new Fp4(a.negate(), b.negate());
    }

    Fp4 multiply(Fp4 o)
    {
        // (a + b v)(c + d v) = (ac + bd*u) + ((a+b)(c+d) - ac - bd) v ; v^2 = u
        Fp2 ac = a.multiply(o.a);
        Fp2 bd = b.multiply(o.b);
        Fp2 mid = a.add(b).multiply(o.a.add(o.b)).subtract(ac).subtract(bd);
        return new Fp4(ac.add(bd.mulU()), mid);
    }

    Fp4 square()
    {
        return multiply(this);
    }

    /**
     * Multiply by v (v^2 = u): (a + b v) * v = b*u + a v.
     */
    Fp4 mulV()
    {
        return new Fp4(b.mulU(), a);
    }

    Fp4 invert()
    {
        // (a + b v)(a - b v) = a^2 - b^2 v^2 = a^2 - b^2 u  (in F_p2)
        Fp2 norm = a.square().subtract(b.square().mulU());
        Fp2 ni = norm.invert();
        return new Fp4(a.multiply(ni), b.negate().multiply(ni));
    }

    public boolean equals(Object other)
    {
        if (this == other)
        {
            return true;
        }
        if (!(other instanceof Fp4))
        {
            return false;
        }
        Fp4 o = (Fp4)other;
        return a.equals(o.a) && b.equals(o.b);
    }

    public int hashCode()
    {
        return a.hashCode() ^ (b.hashCode() * 31);
    }
}
