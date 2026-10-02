package org.bouncycastle.math.ec.sm9;

import org.bouncycastle.util.Arrays;

/**
 * Element of F_p4 = F_p2[v]/(v^2 - u), i.e. v^2 = u, for SM9 (GM/T 0044.5-2016,
 * 1-2-4-12 tower). Written a + b*v with a the low and b the high (v-coefficient)
 * dimension, a, b in {@link Fp2}. Immutable: its thirty-two limbs, a's and then b's, are not
 * changed once it is made.
 * <p>
 * The static methods compute on elements held in int arrays, as {@link Fp2}'s do, for
 * {@link Fp12}, with {@link #MUL_SCRATCH} and {@link #SQR_SCRATCH} limbs of scratch for the product
 * and the square. {@link #mulWide}, {@link #sqrWide} and {@link #mulFp2Wide} give their results as
 * four wide values - see {@link Fp#WIDE} - the coefficients of 1, u, v and u v.
 */
class Fp4
{
    static final int SIZE = 2 * Fp2.SIZE;
    static final int MUL_WIDE_SCRATCH = 6 * Fp.WIDE + 2 * Fp2.SIZE + Fp2.MUL_WIDE_SCRATCH;
    static final int SQR_WIDE_SCRATCH = 6 * Fp.WIDE + Fp2.SIZE + Fp2.SQR_WIDE_SCRATCH;
    static final int MUL_SCRATCH = 4 * Fp.WIDE + MUL_WIDE_SCRATCH;
    static final int SQR_SCRATCH = 4 * Fp.WIDE + SQR_WIDE_SCRATCH;

    private static final long M = 0xFFFFFFFFL;

    static final Fp4 ZERO = new Fp4(Fp2.ZERO, Fp2.ZERO);
    static final Fp4 ONE = new Fp4(Fp2.ONE, Fp2.ZERO);

    final int[] limbs;

    Fp4(Fp2 a, Fp2 b)
    {
        limbs = new int[SIZE];
        System.arraycopy(a.limbs, 0, limbs, 0, Fp2.SIZE);
        System.arraycopy(b.limbs, 0, limbs, Fp2.SIZE, Fp2.SIZE);
    }

    Fp4(int[] limbs)
    {
        this.limbs = limbs;
    }

    /**
     * The constant term a.
     */
    Fp2 a()
    {
        return new Fp2(Arrays.copyOfRange(limbs, 0, Fp2.SIZE));
    }

    /**
     * The v coefficient b.
     */
    Fp2 b()
    {
        return new Fp2(Arrays.copyOfRange(limbs, Fp2.SIZE, SIZE));
    }

    Fp4 add(Fp4 o)
    {
        int[] z = new int[SIZE];
        add(limbs, 0, o.limbs, 0, z, 0);
        return new Fp4(z);
    }

    Fp4 subtract(Fp4 o)
    {
        int[] z = new int[SIZE];
        sub(limbs, 0, o.limbs, 0, z, 0);
        return new Fp4(z);
    }

//    Fp4 negate()
//    {
//        int[] z = new int[SIZE];
//        Fp2.neg(limbs, 0, z, 0);
//        Fp2.neg(limbs, Fp2.SIZE, z, Fp2.SIZE);
//        return new Fp4(z);
//    }

    Fp4 multiply(Fp4 o)
    {
        int[] z = new int[SIZE];
        mul(limbs, 0, o.limbs, 0, z, 0, new int[MUL_SCRATCH], 0);
        return new Fp4(z);
    }

    Fp4 square()
    {
        int[] z = new int[SIZE];
        sqr(limbs, 0, z, 0, new int[SQR_SCRATCH], 0);
        return new Fp4(z);
    }

    /**
     * Multiply by v (v^2 = u): (a + b v) * v = b*u + a v.
     */
    Fp4 mulV()
    {
        int[] z = new int[SIZE];
        addMulV(ZERO.limbs, 0, limbs, 0, z, 0);
        return new Fp4(z);
    }

    Fp4 invert()
    {
        // (a + b v)(a - b v) = a^2 - b^2 v^2 = a^2 - b^2 u  (in F_p2)
        Fp2 a = a(), b = b();
        Fp2 norm = a.square().subtract(b.square().mulU());
        Fp2 ni = norm.invert();
        return new Fp4(a.multiply(ni), b.negate().multiply(ni));
    }

    static void add(int[] x, int xOff, int[] y, int yOff, int[] z, int zOff)
    {
        Fp2.add(x, xOff, y, yOff, z, zOff);
        Fp2.add(x, xOff + Fp2.SIZE, y, yOff + Fp2.SIZE, z, zOff + Fp2.SIZE);
    }

    static void sub(int[] x, int xOff, int[] y, int yOff, int[] z, int zOff)
    {
        Fp2.sub(x, xOff, y, yOff, z, zOff);
        Fp2.sub(x, xOff + Fp2.SIZE, y, yOff + Fp2.SIZE, z, zOff + Fp2.SIZE);
    }

    /**
     * z = x + y v = (x.a + y.b u) + (x.b + y.a) v, v^2 being u. z may be x but not y.
     */
    static void addMulV(int[] x, int xOff, int[] y, int yOff, int[] z, int zOff)
    {
        Fp2.addMulU(x, xOff, y, yOff + Fp2.SIZE, z, zOff);
        Fp2.add(x, xOff + Fp2.SIZE, y, yOff, z, zOff + Fp2.SIZE);
    }

    /**
     * z = x y: the four coefficients {@link #mulWide} forms, each reduced once, where reducing its
     * nine products in F_q would take nine reductions.
     */
    static void mul(int[] x, int xOff, int[] y, int yOff, int[] z, int zOff, int[] t, int tOff)
    {
        mulWide(x, xOff, y, yOff, t, tOff, t, tOff + 4 * Fp.WIDE);
        reduce(t, tOff, z, zOff);
    }

    /**
     * z = x^2: the four coefficients {@link #sqrWide} forms, each reduced once.
     */
    static void sqr(int[] x, int xOff, int[] z, int zOff, int[] t, int tOff)
    {
        sqrWide(x, xOff, t, tOff, t, tOff + 4 * Fp.WIDE);
        reduce(t, tOff, z, zOff);
    }

    /**
     * zz = x y as four wide values, by Karatsuba's form: (a + b v)(c + d v)
     * = (ac + bd u) + ((a + b)(c + d) - ac - bd) v, three F_p2 products formed as {@link Fp2#mulWide}
     * forms them, with a + b and c + d reduced, and none of the four coefficients reduced. Each lies
     * between -4q^2 and 5q^2. t is scratch of {@link #MUL_WIDE_SCRATCH} limbs, which zz may not
     * overlap.
     */
    static void mulWide(int[] x, int xOff, int[] y, int yOff, int[] zz, int zzOff, int[] t, int tOff)
    {
        int bd = tOff + 2 * Fp.WIDE, p = bd + 2 * Fp.WIDE, s = p + 2 * Fp.WIDE, r = s + Fp2.SIZE;
        int tt = r + Fp2.SIZE;
        Fp2.mulWide(x, xOff, y, yOff, t, tOff, t, tt);
        Fp2.mulWide(x, xOff + Fp2.SIZE, y, yOff + Fp2.SIZE, t, bd, t, tt);
        Fp2.add(x, xOff, x, xOff + Fp2.SIZE, t, s);
        Fp2.add(y, yOff, y, yOff + Fp2.SIZE, t, r);
        Fp2.mulWide(t, s, t, r, t, p, t, tt);
        karatsuba(t, tOff, bd, p, zz, zzOff);
    }

    /**
     * zz = x^2 as four wide values: (a + b v)^2 = (a^2 + b^2 u) + ((a + b)^2 - a^2 - b^2) v, three F_p2
     * squares formed as {@link Fp2#sqrWide} forms them, and none of the four coefficients reduced.
     * Each lies between -6q^2 and 5q^2. t is scratch of {@link #SQR_WIDE_SCRATCH} limbs, which zz may
     * not overlap.
     */
    static void sqrWide(int[] x, int xOff, int[] zz, int zzOff, int[] t, int tOff)
    {
        int b2 = tOff + 2 * Fp.WIDE, p = b2 + 2 * Fp.WIDE, s = p + 2 * Fp.WIDE, tt = s + Fp2.SIZE;
        Fp2.sqrWide(x, xOff, t, tOff, t, tt);
        Fp2.sqrWide(x, xOff + Fp2.SIZE, t, b2, t, tt);
        Fp2.add(x, xOff, x, xOff + Fp2.SIZE, t, s);
        Fp2.sqrWide(t, s, t, p, t, tt);
        karatsuba(t, tOff, b2, p, zz, zzOff);
    }

    /**
     * zz = x l for l an element of F_p2, as four wide values: (a + b v) l = a l + b l v, two F_p2
     * products formed as {@link Fp2#mulWide} forms them. t is scratch of
     * {@link Fp2#MUL_WIDE_SCRATCH} limbs, which zz may not overlap.
     */
    static void mulFp2Wide(int[] x, int xOff, int[] l, int lOff, int[] zz, int zzOff, int[] t, int tOff)
    {
        Fp2.mulWide(x, xOff, l, lOff, zz, zzOff, t, tOff);
        Fp2.mulWide(x, xOff + Fp2.SIZE, l, lOff, zz, zzOff + 2 * Fp.WIDE, t, tOff);
    }

    // zz = (ac + bd u) + (p - ac - bd) v, from the wide F_p2 values ac, bd and p in t: bd u being
    // -2 bd_1 + bd_0 u, the coefficient of 1 is ac_0 - 2 bd_1 and that of u is ac_1 + bd_0. The four
    // are formed together, a limb at a time, as Fp.combine forms each, the signed top limbs last
    private static void karatsuba(int[] t, int ac, int bd, int p, int[] zz, int zzOff)
    {
        int w = Fp.WIDE, top = 2 * Fp.SIZE;
        long c0 = 0, c1 = 0, c2 = 0, c3 = 0;
        for (int i = 0; i < top; ++i)
        {
            long a0 = t[ac + i] & M, a1 = t[ac + w + i] & M, b0 = t[bd + i] & M, b1 = t[bd + w + i] & M;
            c0 += a0 - (b1 << 1);                   zz[zzOff + i] = (int)c0;            c0 >>= 32;
            c1 += a1 + b0;                          zz[zzOff + w + i] = (int)c1;        c1 >>= 32;
            c2 += (t[p + i] & M) - a0 - b0;         zz[zzOff + 2 * w + i] = (int)c2;    c2 >>= 32;
            c3 += (t[p + w + i] & M) - a1 - b1;     zz[zzOff + 3 * w + i] = (int)c3;    c3 >>= 32;
        }
        long a0 = t[ac + top], a1 = t[ac + w + top], b0 = t[bd + top], b1 = t[bd + w + top];
        zz[zzOff + top] = (int)(c0 + a0 - (b1 << 1));
        zz[zzOff + w + top] = (int)(c1 + a1 + b0);
        zz[zzOff + 2 * w + top] = (int)(c2 + t[p + top] - a0 - b0);
        zz[zzOff + 3 * w + top] = (int)(c3 + t[p + w + top] - a1 - b1);
    }

    // z = the element of F_p4 whose four coefficients are the wide values from xxOff in xx
    private static void reduce(int[] xx, int xxOff, int[] z, int zOff)
    {
        for (int i = 0; i < 4; ++i)
        {
            Fp.reduceWide(xx, xxOff + i * Fp.WIDE, z, zOff + i * Fp.SIZE);
        }
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
        return Fp2.isEqual(limbs, ((Fp4)other).limbs);
    }

    public int hashCode()
    {
        return Arrays.hashCode(limbs);
    }
}
