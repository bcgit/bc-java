package org.bouncycastle.math.ec.custom.gm;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.raw.Mod;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Prime-field arithmetic for the SM9 256-bit Barreto-Naehrig base field F_q
 * (GM/T 0044.5-2016), used by the G1 curve {@link SM9P256V1Curve}.
 * <p>
 * Unlike {@link SM2P256V1Field} (whose sparse prime admits a fast Solinas
 * reduction and stores elements in the ordinary residue representation), the SM9
 * BN prime is a general 256-bit prime, so this field keeps elements in
 * <b>Montgomery form</b> (a&middot;R mod q, R = 2^256), always fully reduced, below q, and
 * multiplies by Koc, Acar and Kaliski's CIOS method.
 * <p>
 * Addition, subtraction, negation, multiplication, squaring and inversion run the same
 * instructions whatever values they are given: no branch, early exit or array index depends on
 * them, a result is brought below q by a subtraction of q that is always made, its difference kept
 * or discarded through a mask, and the inverse is BouncyCastle's constant-time
 * {@link Mod#modOddInverse}. This is the arithmetic of the F_q the SM9 pairing computes in,
 * org.bouncycastle.math.ec.sm9.Fp, whose elements have the same form.
 */
public class SM9P256V1Field
{
    private static final long M = 0xFFFFFFFFL;

    static final BigInteger Q = SM9P256V1FieldElement.Q;

    static final int[] P = Nat256.fromBigInteger(Q);            // q as 8 little-endian limbs

    // q's limbs, least significant first, and -q^-1 mod 2^32, for the Montgomery product
    private static final long Q0 = P[0] & M, Q1 = P[1] & M, Q2 = P[2] & M, Q3 = P[3] & M;
    private static final long Q4 = P[4] & M, Q5 = P[5] & M, Q6 = P[6] & M, Q7 = P[7] & M;
    private static final long N0 = -Mod.inverse32(P[0]) & M;

    // R^2 mod q, whose Montgomery product with x is x R
    private static final int[] R2 = Nat256.fromBigInteger(BigInteger.ONE.shiftLeft(512).mod(Q));
    static final int[] ONE = Nat256.fromBigInteger(BigInteger.ONE.shiftLeft(256).mod(Q)); // R mod q = 1 in Montgomery form

    // R^3 mod q, for the inverse; 1, whose Montgomery product with x R is x; and 0
    private static final int[] R3 = Nat256.fromBigInteger(BigInteger.ONE.shiftLeft(768).mod(Q));
    private static final int[] UNIT = { 1, 0, 0, 0, 0, 0, 0, 0 };
    private static final int[] ZERO = new int[8];

    // ---- modular add/subtract/negate (Montgomery form is additively homomorphic) ----

    public static void add(int[] x, int[] y, int[] z)
    {
        long c = (x[0] & M) + (y[0] & M);   long t0 = c & M; c >>>= 32;
        c += (x[1] & M) + (y[1] & M);       long t1 = c & M; c >>>= 32;
        c += (x[2] & M) + (y[2] & M);       long t2 = c & M; c >>>= 32;
        c += (x[3] & M) + (y[3] & M);       long t3 = c & M; c >>>= 32;
        c += (x[4] & M) + (y[4] & M);       long t4 = c & M; c >>>= 32;
        c += (x[5] & M) + (y[5] & M);       long t5 = c & M; c >>>= 32;
        c += (x[6] & M) + (y[6] & M);       long t6 = c & M; c >>>= 32;
        c += (x[7] & M) + (y[7] & M);       long t7 = c & M; c >>>= 32;
        reduce(t0, t1, t2, t3, t4, t5, t6, t7, c, z);
    }

    public static void subtract(int[] x, int[] y, int[] z)
    {
        long b = (x[0] & M) - (y[0] & M);   long t0 = b & M; b >>= 32;
        b += (x[1] & M) - (y[1] & M);       long t1 = b & M; b >>= 32;
        b += (x[2] & M) - (y[2] & M);       long t2 = b & M; b >>= 32;
        b += (x[3] & M) - (y[3] & M);       long t3 = b & M; b >>= 32;
        b += (x[4] & M) - (y[4] & M);       long t4 = b & M; b >>= 32;
        b += (x[5] & M) - (y[5] & M);       long t5 = b & M; b >>= 32;
        b += (x[6] & M) - (y[6] & M);       long t6 = b & M; b >>= 32;
        b += (x[7] & M) - (y[7] & M);       long t7 = b & M; b >>= 32;

        // b is -1 if x < y, and 0 otherwise: q is added back under it
        long c = t0 + (Q0 & b);     z[0] = (int)c;  c >>>= 32;
        c += t1 + (Q1 & b);         z[1] = (int)c;  c >>>= 32;
        c += t2 + (Q2 & b);         z[2] = (int)c;  c >>>= 32;
        c += t3 + (Q3 & b);         z[3] = (int)c;  c >>>= 32;
        c += t4 + (Q4 & b);         z[4] = (int)c;  c >>>= 32;
        c += t5 + (Q5 & b);         z[5] = (int)c;  c >>>= 32;
        c += t6 + (Q6 & b);         z[6] = (int)c;  c >>>= 32;
        c += t7 + (Q7 & b);         z[7] = (int)c;
    }

    public static void negate(int[] x, int[] z)
    {
        subtract(ZERO, x, z);
    }

    /**
     * @deprecated Nothing in the library calls this method. Use {@link #add(int[], int[], int[])}
     * with x as both operands instead.
     */
    @Deprecated
    public static void twice(int[] x, int[] z)
    {
        add(x, x, z);
    }

    // ---- Montgomery multiply / square ----

    /**
     * z = x y R^-1 mod q, the Montgomery product, which for x and y in Montgomery form is their
     * product in that form: for each limb x_i of x, a running sum takes x_i y, then the multiple of q
     * that makes its low limb 0, and is shifted down a limb. The sum stays below 2q, so one
     * subtraction of q leaves the result below q. z may be x or y.
     */
    public static void multiply(int[] x, int[] y, int[] z)
    {
        long y0 = y[0] & M, y1 = y[1] & M, y2 = y[2] & M, y3 = y[3] & M;
        long y4 = y[4] & M, y5 = y[5] & M, y6 = y[6] & M, y7 = y[7] & M;
        long t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0, t8 = 0;
        for (int i = 0; i < 8; ++i)
        {
            long xi = x[i] & M;
            long c = t0 + xi * y0;      t0 = c & M; c >>>= 32;
            c += t1 + xi * y1;          t1 = c & M; c >>>= 32;
            c += t2 + xi * y2;          t2 = c & M; c >>>= 32;
            c += t3 + xi * y3;          t3 = c & M; c >>>= 32;
            c += t4 + xi * y4;          t4 = c & M; c >>>= 32;
            c += t5 + xi * y5;          t5 = c & M; c >>>= 32;
            c += t6 + xi * y6;          t6 = c & M; c >>>= 32;
            c += t7 + xi * y7;          t7 = c & M; c >>>= 32;
            c += t8;                    t8 = c & M;
            long t9 = c >>> 32;

            long m = (t0 * N0) & M;
            c = (t0 + m * Q0) >>> 32;
            c += t1 + m * Q1;           t0 = c & M; c >>>= 32;
            c += t2 + m * Q2;           t1 = c & M; c >>>= 32;
            c += t3 + m * Q3;           t2 = c & M; c >>>= 32;
            c += t4 + m * Q4;           t3 = c & M; c >>>= 32;
            c += t5 + m * Q5;           t4 = c & M; c >>>= 32;
            c += t6 + m * Q6;           t5 = c & M; c >>>= 32;
            c += t7 + m * Q7;           t6 = c & M; c >>>= 32;
            c += t8;                    t7 = c & M;
            t8 = t9 + (c >>> 32);
        }
        reduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, z);
    }

    public static void square(int[] x, int[] z)
    {
        multiply(x, x, z);
    }

    /**
     * @deprecated Nothing in the library calls this method. Use {@link #square(int[], int[])} n
     * times instead.
     */
    @Deprecated
    public static void squareN(int[] x, int n, int[] z)
    {
        square(x, z);
        while (--n > 0)
        {
            square(z, z);
        }
    }

    // z = t - q if t, given as nine limbs, is at least q, and t if it is not; t is below 2q
    private static void reduce(long t0, long t1, long t2, long t3, long t4, long t5, long t6, long t7,
        long t8, int[] z)
    {
        long b = t0 - Q0;           long d0 = b & M;    b >>= 32;
        b += t1 - Q1;               long d1 = b & M;    b >>= 32;
        b += t2 - Q2;               long d2 = b & M;    b >>= 32;
        b += t3 - Q3;               long d3 = b & M;    b >>= 32;
        b += t4 - Q4;               long d4 = b & M;    b >>= 32;
        b += t5 - Q5;               long d5 = b & M;    b >>= 32;
        b += t6 - Q6;               long d6 = b & M;    b >>= 32;
        b += t7 - Q7;               long d7 = b & M;    b >>= 32;

        // b + t8 is -1 if t < q, and 0 if not: t is kept under it, and t - q under its complement
        b += t8;
        z[0] = (int)((t0 & b) | (d0 & ~b));
        z[1] = (int)((t1 & b) | (d1 & ~b));
        z[2] = (int)((t2 & b) | (d2 & ~b));
        z[3] = (int)((t3 & b) | (d3 & ~b));
        z[4] = (int)((t4 & b) | (d4 & ~b));
        z[5] = (int)((t5 & b) | (d5 & ~b));
        z[6] = (int)((t6 & b) | (d6 & ~b));
        z[7] = (int)((t7 & b) | (d7 & ~b));
    }

    // ---- conversions and inverse ----

    public static int[] fromBigInteger(BigInteger x)
    {
        // caller guarantees 0 <= x < q; convert to Montgomery form (x*R mod q = montMul(x, R^2))
        int[] z = Nat256.create();
        multiply(Nat256.fromBigInteger(x), R2, z);
        return z;
    }

    public static BigInteger toBigInteger(int[] xMont)
    {
        // leave Montgomery form: the Montgomery product with 1 is xMont * R^-1 mod q
        int[] z = Nat256.create();
        multiply(xMont, UNIT, z);
        return Nat256.toBigInteger(z);
    }

    /**
     * z = x^-1. For x in Montgomery form, x R, {@link Mod#checkedModOddInverse} gives the integer
     * (x R)^-1 = x^-1 R^-1 mod q, and its Montgomery product with R^3 is x^-1 R. Zero has no
     * inverse, and is refused with an ArithmeticException, as the other fields refuse it.
     */
    public static void inv(int[] x, int[] z)
    {
        Mod.checkedModOddInverse(P, x, z);
        multiply(z, R3, z);
    }

    /**
     * @deprecated Nothing in the library calls this method. Use {@link Nat256#isZero(int[])}
     * instead: an element is 0 exactly when its Montgomery form is.
     */
    @Deprecated
    public static boolean isZero(int[] x)
    {
        return Nat256.isZero(x);
    }

    // the draws random and randomMult make before they fail, as the draws of the arithmetic the
    // SM9 pairing, G_T and G2 compute in do: a source that yields nothing usable - only zeros, or
    // only ones - would otherwise keep them drawing without end, and ECPoint.normalize() takes the
    // factor it blinds an inversion with from the default source, whatever source its caller had
    private static final int MAX_DRAWS = 1000;

    /**
     * A uniformly random element, drawn as its Montgomery-form limbs: the form is a bijection on
     * [0, q), so a uniform representation is a uniform element. The same rejection sampling
     * {@link SM2P256V1Field#random} uses; q is a little over 2^255.5, so under 1.5 draws on
     * average, and if none of a thousand draws is below q it throws IllegalStateException.
     */
    public static void random(SecureRandom r, int[] z)
    {
        byte[] bb = new byte[8 * 4];
        for (int i = 0; i < MAX_DRAWS; ++i)
        {
            r.nextBytes(bb);
            Pack.littleEndianToInt(bb, 0, z, 0, 8);
            if (0 != Nat.lessThan(8, z, P))
            {
                Arrays.clear(bb);
                return;
            }
        }
        // the draws are erased on either path, as Fp.random erases its own
        Arrays.clear(bb);
        throw new IllegalStateException("SM9 arithmetic could not draw a usable random element");
    }

    /**
     * A uniformly random non-zero element, as {@link #random} draws them; if none of a thousand of
     * them is other than 0, it throws IllegalStateException.
     */
    public static void randomMult(SecureRandom r, int[] z)
    {
        for (int i = 0; i < MAX_DRAWS; ++i)
        {
            random(r, z);
            if (!Nat256.isZero(z))
            {
                return;
            }
        }
        throw new IllegalStateException("SM9 arithmetic could not draw a usable random element");
    }

    private SM9P256V1Field()
    {
    }
}
