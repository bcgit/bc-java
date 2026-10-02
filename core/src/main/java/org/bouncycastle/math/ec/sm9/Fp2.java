package org.bouncycastle.math.ec.sm9;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.util.Arrays;

/**
 * Element of F_p2 = F_p[u]/(u^2 + 2), i.e. u^2 = -2, for the SM9 256-bit BN curve
 * (GM/T 0044.5-2016). Written a + b*u with a the low (constant) and b the high
 * (u-coefficient) dimension. Immutable: its sixteen limbs, a's and then b's, each in the form
 * {@link Fp} computes on, are not changed once it is made.
 * <p>
 * The static methods compute on elements held in int arrays, as {@link Fp}'s do, for {@link Fp4}
 * and {@link Fp12}: an element is sixteen limbs from an offset, and a method that needs room for
 * intermediate values takes it as a scratch array and offset, of {@link #MUL_SCRATCH} limbs for
 * the product and {@link #SQR_SCRATCH} for the square. A result may be written over the operands
 * unless the method says otherwise. {@link #mulWide} and {@link #sqrWide} give the product and the
 * square as two wide values - see {@link Fp#WIDE} - for the products and squares over this field
 * to add into the coefficients of theirs before they reduce them.
 */
class Fp2
{
    static final int SIZE = 2 * Fp.SIZE;
    static final int MUL_WIDE_SCRATCH = 2 * Fp.SIZE + 3 * Fp.WIDE;
    static final int SQR_WIDE_SCRATCH = 3 * Fp.WIDE;
    static final int MUL_SCRATCH = 2 * Fp.WIDE + MUL_WIDE_SCRATCH;
    static final int SQR_SCRATCH = 2 * Fp.WIDE + SQR_WIDE_SCRATCH;

    private static final long M = 0xFFFFFFFFL;

    static final Fp2 ZERO = new Fp2(new int[SIZE]);
    static final Fp2 ONE = new Fp2(BigInteger.ONE, BigInteger.ZERO);

    final int[] limbs;

    /**
     * The element a + b u, for public values a and b, which are reduced mod q.
     */
    Fp2(BigInteger a, BigInteger b)
    {
        limbs = new int[SIZE];
        Fp.fromBigInteger(a, limbs, 0);
        Fp.fromBigInteger(b, limbs, Fp.SIZE);
    }

    Fp2(int[] limbs)
    {
        this.limbs = limbs;
    }

    /**
     * A random element of F_p2 other than zero, for the random representatives the pairing and
     * the G2 scalar multiplication start from: its constant term is drawn from [1, q - 1] and its
     * u-coefficient from [0, q - 1].
     */
    static Fp2 randomNonZero()
    {
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        int[] z = new int[SIZE];
        Fp.randomNonZero(random, z, 0);
        Fp.random(random, z, Fp.SIZE);
        return new Fp2(z);
    }

    boolean isZero()
    {
        return Fp.isZero(limbs, 0) & Fp.isZero(limbs, Fp.SIZE);
    }

    Fp2 add(Fp2 o)
    {
        int[] z = new int[SIZE];
        add(limbs, 0, o.limbs, 0, z, 0);
        return new Fp2(z);
    }

    Fp2 subtract(Fp2 o)
    {
        int[] z = new int[SIZE];
        sub(limbs, 0, o.limbs, 0, z, 0);
        return new Fp2(z);
    }

    Fp2 negate()
    {
        int[] z = new int[SIZE];
        neg(limbs, 0, z, 0);
        return new Fp2(z);
    }

    Fp2 multiply(Fp2 o)
    {
        int[] z = new int[SIZE];
        mul(limbs, 0, o.limbs, 0, z, 0, new int[MUL_SCRATCH], 0);
        return new Fp2(z);
    }

    Fp2 square()
    {
        int[] z = new int[SIZE];
        sqr(limbs, 0, z, 0, new int[SQR_SCRATCH], 0);
        return new Fp2(z);
    }

    /**
     * Multiply by u (u^2 = -2): (a + b u) * u = -2b + a u.
     */
    Fp2 mulU()
    {
        int[] z = new int[SIZE];
        addMulU(ZERO.limbs, 0, limbs, 0, z, 0);
        return new Fp2(z);
    }

    /**
     * The conjugate a - b u, which is this element's q-th power: u^q = u (u^2)^((q - 1)/2) = -u.
     */
    Fp2 conjugate()
    {
        int[] z = new int[SIZE];
        conj(limbs, 0, z, 0);
        return new Fp2(z);
    }

    Fp2 invert()
    {
        int[] z = new int[SIZE];
        if (!inv(limbs, 0, z, 0))
        {
            // only zero has norm zero, u^2 + 2 being irreducible, and the F_p4 and F_p12 inverses
            // each reduce to one of these - so this is where the tower says zero has no inverse,
            // in the G1 field's words
            throw new ArithmeticException("Inverse does not exist.");
        }
        return new Fp2(z);
    }

    static void add(int[] x, int xOff, int[] y, int yOff, int[] z, int zOff)
    {
        Fp.add(x, xOff, y, yOff, z, zOff);
        Fp.add(x, xOff + Fp.SIZE, y, yOff + Fp.SIZE, z, zOff + Fp.SIZE);
    }

    static void sub(int[] x, int xOff, int[] y, int yOff, int[] z, int zOff)
    {
        Fp.sub(x, xOff, y, yOff, z, zOff);
        Fp.sub(x, xOff + Fp.SIZE, y, yOff + Fp.SIZE, z, zOff + Fp.SIZE);
    }

    static void neg(int[] x, int xOff, int[] z, int zOff)
    {
        Fp.neg(x, xOff, z, zOff);
        Fp.neg(x, xOff + Fp.SIZE, z, zOff + Fp.SIZE);
    }

    static void conj(int[] x, int xOff, int[] z, int zOff)
    {
        System.arraycopy(x, xOff, z, zOff, Fp.SIZE);
        Fp.neg(x, xOff + Fp.SIZE, z, zOff + Fp.SIZE);
    }

    /**
     * z = x + y u = (x.a - 2 y.b) + (x.b + y.a) u, u^2 being -2. z may be x but not y.
     */
    static void addMulU(int[] x, int xOff, int[] y, int yOff, int[] z, int zOff)
    {
        Fp.sub(x, xOff, y, yOff + Fp.SIZE, z, zOff);
        Fp.sub(z, zOff, y, yOff + Fp.SIZE, z, zOff);
        Fp.add(x, xOff + Fp.SIZE, y, yOff, z, zOff + Fp.SIZE);
    }

    /**
     * z = x y: the two coefficients {@link #mulWide} forms, each reduced once, where reducing its
     * three products in F_q would take three reductions.
     */
    static void mul(int[] x, int xOff, int[] y, int yOff, int[] z, int zOff, int[] t, int tOff)
    {
        mulWide(x, xOff, y, yOff, t, tOff, t, tOff + 2 * Fp.WIDE);
        Fp.reduceWide(t, tOff, z, zOff);
        Fp.reduceWide(t, tOff + Fp.WIDE, z, zOff + Fp.SIZE);
    }

    /**
     * z = x^2: the two coefficients {@link #sqrWide} forms, each reduced once.
     */
    static void sqr(int[] x, int xOff, int[] z, int zOff, int[] t, int tOff)
    {
        sqrWide(x, xOff, t, tOff, t, tOff + 2 * Fp.WIDE);
        Fp.reduceWide(t, tOff, z, zOff);
        Fp.reduceWide(t, tOff + Fp.WIDE, z, zOff + Fp.SIZE);
    }

    /**
     * zz = x y as two wide values, its constant term and then its u coefficient, by Karatsuba's form:
     * (a + b u)(c + d u) = (ac - 2bd) + ((a + b)(c + d) - ac - bd) u, three products in F_q formed in
     * full, with a + b and c + d reduced. Each coefficient lies between -2q^2 and q^2. t is scratch of
     * {@link #MUL_WIDE_SCRATCH} limbs, which zz may not overlap.
     */
    static void mulWide(int[] x, int xOff, int[] y, int yOff, int[] zz, int zzOff, int[] t, int tOff)
    {
        int r = tOff + Fp.SIZE, ac = tOff + 2 * Fp.SIZE, bd = ac + Fp.WIDE, p = bd + Fp.WIDE;
        Fp.add(x, xOff, x, xOff + Fp.SIZE, t, tOff);
        Fp.add(y, yOff, y, yOff + Fp.SIZE, t, r);
        Fp.mulWide(x, xOff, y, yOff, t, ac);
        Fp.mulWide(x, xOff + Fp.SIZE, y, yOff + Fp.SIZE, t, bd);
        Fp.mulWide(t, tOff, t, r, t, p);

        // ac - 2bd and p - ac - bd, together, a limb at a time, as Fp.combine forms each: the products
        // are below q^2, and so their top limbs 0
        long c0 = 0, c1 = 0;
        for (int i = 0; i < 2 * Fp.SIZE; ++i)
        {
            long a = t[ac + i] & M, b = t[bd + i] & M;
            c0 += a - (b << 1);                 zz[zzOff + i] = (int)c0;                c0 >>= 32;
            c1 += (t[p + i] & M) - a - b;       zz[zzOff + Fp.WIDE + i] = (int)c1;      c1 >>= 32;
        }
        zz[zzOff + 2 * Fp.SIZE] = (int)c0;
        zz[zzOff + Fp.WIDE + 2 * Fp.SIZE] = (int)c1;
    }

    /**
     * zz = x^2 as two wide values: (a + b u)^2 = (a^2 - 2b^2) + 2ab u, two squares and a product in
     * F_q formed in full, a square taking thirty-six products of limbs where a product takes
     * sixty-four. The constant term lies between -2q^2 and q^2 and the u coefficient between 0 and
     * 2q^2. t is scratch of {@link #SQR_WIDE_SCRATCH} limbs, which zz may not overlap.
     */
    static void sqrWide(int[] x, int xOff, int[] zz, int zzOff, int[] t, int tOff)
    {
        int b2 = tOff + Fp.WIDE, ab = b2 + Fp.WIDE;
        Fp.sqrWide(x, xOff, t, tOff);
        Fp.sqrWide(x, xOff + Fp.SIZE, t, b2);
        Fp.mulWide(x, xOff, x, xOff + Fp.SIZE, t, ab);

        // a^2 - 2b^2 and 2ab, together, as mulWide forms its two
        long c0 = 0, c1 = 0;
        for (int i = 0; i < 2 * Fp.SIZE; ++i)
        {
            c0 += (t[tOff + i] & M) - ((t[b2 + i] & M) << 1);  zz[zzOff + i] = (int)c0;             c0 >>= 32;
            c1 += (t[ab + i] & M) << 1;                         zz[zzOff + Fp.WIDE + i] = (int)c1;   c1 >>= 32;
        }
        zz[zzOff + 2 * Fp.SIZE] = (int)c0;
        zz[zzOff + Fp.WIDE + 2 * Fp.SIZE] = (int)c1;
    }

    /**
     * z = x s, for s an element of F_q, which z may not be written over.
     */
    static void mulFp(int[] x, int xOff, int[] s, int sOff, int[] z, int zOff)
    {
        Fp.mul(x, xOff, s, sOff, z, zOff);
        Fp.mul(x, xOff + Fp.SIZE, s, sOff, z, zOff + Fp.SIZE);
    }

    /**
     * z = x^-1, or false for x = 0: (a + b u)^-1 = (a - b u) / (a^2 + 2b^2). The norm is inverted
     * as (norm s)^-1 s for a random non-zero s, so the inversion runs on a value that tells nothing
     * about the norm - the countermeasure {@link org.bouncycastle.math.ec.ECPoint#normalize()}
     * applies, for the side channel Drucker and Gueron identified, although the inversion itself now
     * runs in constant time. The KGC's G2 scalar multiplications, which run on its secrets - [ks]P2
     * for a signature master key and [t2]P2 for each encryption user key it derives - reach it once,
     * to bring their Jacobian result back to affine coordinates; so do the affine addition and
     * doubling of G2 points, and the pairing's final exponentiation, through the F_p4 and F_p12
     * inverses. (The Miller loop works in projective coordinates and inverts nothing.)
     */
    static boolean inv(int[] x, int xOff, int[] z, int zOff)
    {
        int norm = 0, factor = Fp.SIZE;
        int[] t = new int[2 * Fp.SIZE];
        Fp.sqr(x, xOff, t, norm);
        Fp.sqr(x, xOff + Fp.SIZE, t, factor);                   // b^2, until the factor is drawn
        Fp.add(t, norm, t, factor, t, norm);
        Fp.add(t, norm, t, factor, t, norm);                    // a^2 + 2b^2
        if (Fp.isZero(t, norm))
        {
            return false;
        }
        Fp.randomNonZero(CryptoServicesRegistrar.getSecureRandom(), t, factor);
        Fp.mul(t, norm, t, factor, t, norm);
        Fp.inv(t, norm, t, norm);
        Fp.mul(t, norm, t, factor, t, norm);                    // (a^2 + 2b^2)^-1
        mulFp(x, xOff, t, norm, z, zOff);
        Fp.neg(z, zOff + Fp.SIZE, z, zOff + Fp.SIZE);
        Arrays.clear(t);
        return true;
    }

    /**
     * 1 if the element at xOff is 0 and 0 if not, all its limbs read, for a mask.
     */
    static int zeroBit(int[] x, int xOff)
    {
        int d = 0;
        for (int i = 0; i < SIZE; ++i)
        {
            d |= x[xOff + i];
        }
        return 1 + ((d | -d) >> 31);
    }

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
        return isEqual(limbs, ((Fp2)other).limbs);
    }

    public int hashCode()
    {
        return Arrays.hashCode(limbs);
    }

    // whether x and y hold the same limbs, which for the reduced form here is whether they are the
    // same element; compared in full, so the time taken does not say where they differ
    static boolean isEqual(int[] x, int[] y)
    {
        int d = 0;
        for (int i = 0; i < x.length; ++i)
        {
            d |= x[i] ^ y[i];
        }
        return d == 0;
    }
}
