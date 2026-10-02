package org.bouncycastle.math.ec.sm9;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.custom.gm.SM9P256V1Curve;
import org.bouncycastle.math.raw.Mod;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Pack;

/**
 * Arithmetic in F_q, the base field of the SM9 256-bit BN curve (GM/T 0044.5-2016), on which
 * {@link Fp2}, {@link Fp4} and {@link Fp12} are built. An element is held as eight 32-bit limbs,
 * least significant first, at an offset in an int array, in Montgomery form - x R mod q for
 * R = 2^256 - and is always fully reduced, below q.
 * <p>
 * Each operation runs the same instructions whatever values it is given: no branch, early exit or
 * array index depends on them, and a result is brought below q by a subtraction of q that is always
 * made, its difference kept or discarded through a mask. The BigInteger arithmetic the tower used
 * before could not give that - its running time follows the magnitude of the values - and the
 * values here include the users' private keys. The exceptions take public or random values:
 * {@link #fromBigInteger}, for constants and public inputs, and the random draws, which draw again
 * when a draw is not below q.
 * <p>
 * The products and squares of {@link Fp2}, {@link Fp4} and {@link Fp12} reduce each coefficient of
 * their result once: they form the products in F_q their formulas call for in full, as the wide
 * values of {@link #WIDE}, add and subtract those into each coefficient unreduced, and bring each
 * coefficient to an element by {@link #reduceWide} - twelve reductions for a product in F_p12, where
 * reducing each of its fifty-four products in F_q as {@link #mul} does would take fifty-four.
 */
final class Fp
{
    static final int SIZE = 8;

    static final BigInteger Q = SM9P256V1Curve.q;

    private static final long M = 0xFFFFFFFFL;

    private static final int[] P = Nat256.fromBigInteger(Q);

    // q's limbs, least significant first, and -q^-1 mod 2^32, for the Montgomery product
    private static final long Q0 = P[0] & M, Q1 = P[1] & M, Q2 = P[2] & M, Q3 = P[3] & M;
    private static final long Q4 = P[4] & M, Q5 = P[5] & M, Q6 = P[6] & M, Q7 = P[7] & M;
    private static final long N0 = -Mod.inverse32(P[0]) & M;

    // R^2 mod q, whose Montgomery product with x is x R; R^3 mod q, for the inverse; and 1, whose
    // Montgomery product with x R is x
    private static final int[] R2 = Nat256.fromBigInteger(BigInteger.ONE.shiftLeft(512).mod(Q));
    private static final int[] R3 = Nat256.fromBigInteger(BigInteger.ONE.shiftLeft(768).mod(Q));
    private static final int[] UNIT = { 1, 0, 0, 0, 0, 0, 0, 0 };
    private static final int[] ZERO = new int[SIZE];

    /**
     * 1, in Montgomery form: R mod q.
     */
    static final int[] ONE = Nat256.fromBigInteger(BigInteger.ONE.shiftLeft(256).mod(Q));

    /**
     * The number of limbs of a wide value: an integer below 2^543 in magnitude, as seventeen 32-bit
     * limbs, least significant first, the top one signed, standing for the element whose form its
     * Montgomery reduction {@link #reduceWide} gives. The product {@link #mulWide} forms of the forms
     * of two elements x and y is congruent to x y R^2 mod q, and so stands for x y, as does every sum
     * of such products, times small integers, that {@link #combine} forms - the sums and differences
     * each coefficient of a product or a square in the extension fields is made of.
     */
    static final int WIDE = 2 * SIZE + 1;

    // 512 q, as nine limbs, which reduceWide adds to its value before it estimates the quotient, and
    // floor(2^52 / (q_7 + 1)) for q_7 the top limb of q, the constant it estimates it by
    private static final int[] Q512 = Nat.fromBigInteger(288, Q.shiftLeft(9));
    private static final long O0 = Q512[0] & M, O1 = Q512[1] & M, O2 = Q512[2] & M, O3 = Q512[3] & M;
    private static final long O4 = Q512[4] & M, O5 = Q512[5] & M, O6 = Q512[6] & M, O7 = Q512[7] & M;
    private static final long O8 = Q512[8] & M;
    private static final long QUOTIENT = (1L << 52) / (Q7 + 1);

    static void add(int[] x, int xOff, int[] y, int yOff, int[] z, int zOff)
    {
        long c = (x[xOff] & M) + (y[yOff] & M);             long t0 = c & M; c >>>= 32;
        c += (x[xOff + 1] & M) + (y[yOff + 1] & M);         long t1 = c & M; c >>>= 32;
        c += (x[xOff + 2] & M) + (y[yOff + 2] & M);         long t2 = c & M; c >>>= 32;
        c += (x[xOff + 3] & M) + (y[yOff + 3] & M);         long t3 = c & M; c >>>= 32;
        c += (x[xOff + 4] & M) + (y[yOff + 4] & M);         long t4 = c & M; c >>>= 32;
        c += (x[xOff + 5] & M) + (y[yOff + 5] & M);         long t5 = c & M; c >>>= 32;
        c += (x[xOff + 6] & M) + (y[yOff + 6] & M);         long t6 = c & M; c >>>= 32;
        c += (x[xOff + 7] & M) + (y[yOff + 7] & M);         long t7 = c & M; c >>>= 32;
        reduce(t0, t1, t2, t3, t4, t5, t6, t7, c, z, zOff);
    }

    static void sub(int[] x, int xOff, int[] y, int yOff, int[] z, int zOff)
    {
        long b = (x[xOff] & M) - (y[yOff] & M);             long t0 = b & M; b >>= 32;
        b += (x[xOff + 1] & M) - (y[yOff + 1] & M);         long t1 = b & M; b >>= 32;
        b += (x[xOff + 2] & M) - (y[yOff + 2] & M);         long t2 = b & M; b >>= 32;
        b += (x[xOff + 3] & M) - (y[yOff + 3] & M);         long t3 = b & M; b >>= 32;
        b += (x[xOff + 4] & M) - (y[yOff + 4] & M);         long t4 = b & M; b >>= 32;
        b += (x[xOff + 5] & M) - (y[yOff + 5] & M);         long t5 = b & M; b >>= 32;
        b += (x[xOff + 6] & M) - (y[yOff + 6] & M);         long t6 = b & M; b >>= 32;
        b += (x[xOff + 7] & M) - (y[yOff + 7] & M);         long t7 = b & M; b >>= 32;

        // b is -1 if x < y, and 0 otherwise: q is added back under it
        long c = t0 + (Q0 & b);     z[zOff] = (int)c;       c >>>= 32;
        c += t1 + (Q1 & b);         z[zOff + 1] = (int)c;   c >>>= 32;
        c += t2 + (Q2 & b);         z[zOff + 2] = (int)c;   c >>>= 32;
        c += t3 + (Q3 & b);         z[zOff + 3] = (int)c;   c >>>= 32;
        c += t4 + (Q4 & b);         z[zOff + 4] = (int)c;   c >>>= 32;
        c += t5 + (Q5 & b);         z[zOff + 5] = (int)c;   c >>>= 32;
        c += t6 + (Q6 & b);         z[zOff + 6] = (int)c;   c >>>= 32;
        c += t7 + (Q7 & b);         z[zOff + 7] = (int)c;
    }

    static void neg(int[] x, int xOff, int[] z, int zOff)
    {
        sub(ZERO, 0, x, xOff, z, zOff);
    }

    /**
     * z = x y R^-1 mod q, the Montgomery product, which for x and y in Montgomery form is their
     * product in that form. This is Koc, Acar and Kaliski's CIOS method: for each limb x_i of x, a
     * running sum takes x_i y, then the multiple of q that makes its low limb 0, and is shifted down a
     * limb. The sum stays below 2q, so one subtraction of q leaves the result below q. z may be x or
     * y.
     */
    static void mul(int[] x, int xOff, int[] y, int yOff, int[] z, int zOff)
    {
        long y0 = y[yOff] & M, y1 = y[yOff + 1] & M, y2 = y[yOff + 2] & M, y3 = y[yOff + 3] & M;
        long y4 = y[yOff + 4] & M, y5 = y[yOff + 5] & M, y6 = y[yOff + 6] & M, y7 = y[yOff + 7] & M;
        long t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0, t8 = 0;
        for (int i = 0; i < SIZE; ++i)
        {
            long xi = x[xOff + i] & M;
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
        reduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, z, zOff);
    }

    static void sqr(int[] x, int xOff, int[] z, int zOff)
    {
        mul(x, xOff, x, xOff, z, zOff);
    }

    /**
     * zz = x y in full, as a wide value - see {@link #WIDE} - below q^2 for two elements: row by row,
     * x_i y added into the limbs from i, the limbs of the sum held in locals.
     */
    static void mulWide(int[] x, int xOff, int[] y, int yOff, int[] zz, int zzOff)
    {
        long y0 = y[yOff] & M, y1 = y[yOff + 1] & M, y2 = y[yOff + 2] & M, y3 = y[yOff + 3] & M;
        long y4 = y[yOff + 4] & M, y5 = y[yOff + 5] & M, y6 = y[yOff + 6] & M, y7 = y[yOff + 7] & M;

        long xi = x[xOff] & M;
        long c = xi * y0;           long z0 = c & M;  c >>>= 32;
        c += xi * y1;               long z1 = c & M;  c >>>= 32;
        c += xi * y2;               long z2 = c & M;  c >>>= 32;
        c += xi * y3;               long z3 = c & M;  c >>>= 32;
        c += xi * y4;               long z4 = c & M;  c >>>= 32;
        c += xi * y5;               long z5 = c & M;  c >>>= 32;
        c += xi * y6;               long z6 = c & M;  c >>>= 32;
        c += xi * y7;               long z7 = c & M;  c >>>= 32;
        long z8 = c;

        xi = x[xOff + 1] & M;
        c = z1 + xi * y0;           z1 = c & M;       c >>>= 32;
        c += z2 + xi * y1;          z2 = c & M;       c >>>= 32;
        c += z3 + xi * y2;          z3 = c & M;       c >>>= 32;
        c += z4 + xi * y3;          z4 = c & M;       c >>>= 32;
        c += z5 + xi * y4;          z5 = c & M;       c >>>= 32;
        c += z6 + xi * y5;          z6 = c & M;       c >>>= 32;
        c += z7 + xi * y6;          z7 = c & M;       c >>>= 32;
        c += z8 + xi * y7;          z8 = c & M;       c >>>= 32;
        long z9 = c;

        xi = x[xOff + 2] & M;
        c = z2 + xi * y0;           z2 = c & M;       c >>>= 32;
        c += z3 + xi * y1;          z3 = c & M;       c >>>= 32;
        c += z4 + xi * y2;          z4 = c & M;       c >>>= 32;
        c += z5 + xi * y3;          z5 = c & M;       c >>>= 32;
        c += z6 + xi * y4;          z6 = c & M;       c >>>= 32;
        c += z7 + xi * y5;          z7 = c & M;       c >>>= 32;
        c += z8 + xi * y6;          z8 = c & M;       c >>>= 32;
        c += z9 + xi * y7;          z9 = c & M;       c >>>= 32;
        long z10 = c;

        xi = x[xOff + 3] & M;
        c = z3 + xi * y0;           z3 = c & M;       c >>>= 32;
        c += z4 + xi * y1;          z4 = c & M;       c >>>= 32;
        c += z5 + xi * y2;          z5 = c & M;       c >>>= 32;
        c += z6 + xi * y3;          z6 = c & M;       c >>>= 32;
        c += z7 + xi * y4;          z7 = c & M;       c >>>= 32;
        c += z8 + xi * y5;          z8 = c & M;       c >>>= 32;
        c += z9 + xi * y6;          z9 = c & M;       c >>>= 32;
        c += z10 + xi * y7;         z10 = c & M;      c >>>= 32;
        long z11 = c;

        xi = x[xOff + 4] & M;
        c = z4 + xi * y0;           z4 = c & M;       c >>>= 32;
        c += z5 + xi * y1;          z5 = c & M;       c >>>= 32;
        c += z6 + xi * y2;          z6 = c & M;       c >>>= 32;
        c += z7 + xi * y3;          z7 = c & M;       c >>>= 32;
        c += z8 + xi * y4;          z8 = c & M;       c >>>= 32;
        c += z9 + xi * y5;          z9 = c & M;       c >>>= 32;
        c += z10 + xi * y6;         z10 = c & M;      c >>>= 32;
        c += z11 + xi * y7;         z11 = c & M;      c >>>= 32;
        long z12 = c;

        xi = x[xOff + 5] & M;
        c = z5 + xi * y0;           z5 = c & M;       c >>>= 32;
        c += z6 + xi * y1;          z6 = c & M;       c >>>= 32;
        c += z7 + xi * y2;          z7 = c & M;       c >>>= 32;
        c += z8 + xi * y3;          z8 = c & M;       c >>>= 32;
        c += z9 + xi * y4;          z9 = c & M;       c >>>= 32;
        c += z10 + xi * y5;         z10 = c & M;      c >>>= 32;
        c += z11 + xi * y6;         z11 = c & M;      c >>>= 32;
        c += z12 + xi * y7;         z12 = c & M;      c >>>= 32;
        long z13 = c;

        xi = x[xOff + 6] & M;
        c = z6 + xi * y0;           z6 = c & M;       c >>>= 32;
        c += z7 + xi * y1;          z7 = c & M;       c >>>= 32;
        c += z8 + xi * y2;          z8 = c & M;       c >>>= 32;
        c += z9 + xi * y3;          z9 = c & M;       c >>>= 32;
        c += z10 + xi * y4;         z10 = c & M;      c >>>= 32;
        c += z11 + xi * y5;         z11 = c & M;      c >>>= 32;
        c += z12 + xi * y6;         z12 = c & M;      c >>>= 32;
        c += z13 + xi * y7;         z13 = c & M;      c >>>= 32;
        long z14 = c;

        xi = x[xOff + 7] & M;
        c = z7 + xi * y0;           z7 = c & M;       c >>>= 32;
        c += z8 + xi * y1;          z8 = c & M;       c >>>= 32;
        c += z9 + xi * y2;          z9 = c & M;       c >>>= 32;
        c += z10 + xi * y3;         z10 = c & M;      c >>>= 32;
        c += z11 + xi * y4;         z11 = c & M;      c >>>= 32;
        c += z12 + xi * y5;         z12 = c & M;      c >>>= 32;
        c += z13 + xi * y6;         z13 = c & M;      c >>>= 32;
        c += z14 + xi * y7;         z14 = c & M;      c >>>= 32;
        long z15 = c;

        zz[zzOff] = (int)z0;
        zz[zzOff + 1] = (int)z1;
        zz[zzOff + 2] = (int)z2;
        zz[zzOff + 3] = (int)z3;
        zz[zzOff + 4] = (int)z4;
        zz[zzOff + 5] = (int)z5;
        zz[zzOff + 6] = (int)z6;
        zz[zzOff + 7] = (int)z7;
        zz[zzOff + 8] = (int)z8;
        zz[zzOff + 9] = (int)z9;
        zz[zzOff + 10] = (int)z10;
        zz[zzOff + 11] = (int)z11;
        zz[zzOff + 12] = (int)z12;
        zz[zzOff + 13] = (int)z13;
        zz[zzOff + 14] = (int)z14;
        zz[zzOff + 15] = (int)z15;
        zz[zzOff + 16] = 0;
    }

    /**
     * zz = x^2 in full, as a wide value, as {@link #mulWide} forms x x: the products x_i x_j for
     * i &lt; j, twice their sum, and the squares x_i^2 - thirty-six products of limbs where mulWide
     * takes sixty-four.
     */
    static void sqrWide(int[] x, int xOff, int[] zz, int zzOff)
    {
        long x0 = x[xOff] & M, x1 = x[xOff + 1] & M, x2 = x[xOff + 2] & M, x3 = x[xOff + 3] & M;
        long x4 = x[xOff + 4] & M, x5 = x[xOff + 5] & M, x6 = x[xOff + 6] & M, x7 = x[xOff + 7] & M;

        // the products x_i x_j for i < j, a row for each i
        long c = x0 * x1;           long z1 = c & M;  c >>>= 32;
        c += x0 * x2;               long z2 = c & M;  c >>>= 32;
        c += x0 * x3;               long z3 = c & M;  c >>>= 32;
        c += x0 * x4;               long z4 = c & M;  c >>>= 32;
        c += x0 * x5;               long z5 = c & M;  c >>>= 32;
        c += x0 * x6;               long z6 = c & M;  c >>>= 32;
        c += x0 * x7;               long z7 = c & M;  c >>>= 32;
        long z8 = c;

        c = z3 + x1 * x2;           z3 = c & M;       c >>>= 32;
        c += z4 + x1 * x3;          z4 = c & M;       c >>>= 32;
        c += z5 + x1 * x4;          z5 = c & M;       c >>>= 32;
        c += z6 + x1 * x5;          z6 = c & M;       c >>>= 32;
        c += z7 + x1 * x6;          z7 = c & M;       c >>>= 32;
        c += z8 + x1 * x7;          z8 = c & M;       c >>>= 32;
        long z9 = c;

        c = z5 + x2 * x3;           z5 = c & M;       c >>>= 32;
        c += z6 + x2 * x4;          z6 = c & M;       c >>>= 32;
        c += z7 + x2 * x5;          z7 = c & M;       c >>>= 32;
        c += z8 + x2 * x6;          z8 = c & M;       c >>>= 32;
        c += z9 + x2 * x7;          z9 = c & M;       c >>>= 32;
        long z10 = c;

        c = z7 + x3 * x4;           z7 = c & M;       c >>>= 32;
        c += z8 + x3 * x5;          z8 = c & M;       c >>>= 32;
        c += z9 + x3 * x6;          z9 = c & M;       c >>>= 32;
        c += z10 + x3 * x7;         z10 = c & M;      c >>>= 32;
        long z11 = c;

        c = z9 + x4 * x5;           z9 = c & M;       c >>>= 32;
        c += z10 + x4 * x6;         z10 = c & M;      c >>>= 32;
        c += z11 + x4 * x7;         z11 = c & M;      c >>>= 32;
        long z12 = c;

        c = z11 + x5 * x6;          z11 = c & M;      c >>>= 32;
        c += z12 + x5 * x7;         z12 = c & M;      c >>>= 32;
        long z13 = c;

        c = z13 + x6 * x7;          z13 = c & M;      c >>>= 32;
        long z14 = c;

        // twice their sum, and the squares x_i^2
        long d = x0 * x0;
        c = d & M;                      zz[zzOff] = (int)c;       c >>>= 32;
        c += (z1 << 1) + (d >>> 32);    zz[zzOff + 1] = (int)c;   c >>>= 32;
        d = x1 * x1;
        c += (z2 << 1) + (d & M);       zz[zzOff + 2] = (int)c;   c >>>= 32;
        c += (z3 << 1) + (d >>> 32);    zz[zzOff + 3] = (int)c;   c >>>= 32;
        d = x2 * x2;
        c += (z4 << 1) + (d & M);       zz[zzOff + 4] = (int)c;   c >>>= 32;
        c += (z5 << 1) + (d >>> 32);    zz[zzOff + 5] = (int)c;   c >>>= 32;
        d = x3 * x3;
        c += (z6 << 1) + (d & M);       zz[zzOff + 6] = (int)c;   c >>>= 32;
        c += (z7 << 1) + (d >>> 32);    zz[zzOff + 7] = (int)c;   c >>>= 32;
        d = x4 * x4;
        c += (z8 << 1) + (d & M);       zz[zzOff + 8] = (int)c;   c >>>= 32;
        c += (z9 << 1) + (d >>> 32);    zz[zzOff + 9] = (int)c;   c >>>= 32;
        d = x5 * x5;
        c += (z10 << 1) + (d & M);      zz[zzOff + 10] = (int)c;  c >>>= 32;
        c += (z11 << 1) + (d >>> 32);   zz[zzOff + 11] = (int)c;  c >>>= 32;
        d = x6 * x6;
        c += (z12 << 1) + (d & M);      zz[zzOff + 12] = (int)c;  c >>>= 32;
        c += (z13 << 1) + (d >>> 32);   zz[zzOff + 13] = (int)c;  c >>>= 32;
        d = x7 * x7;
        c += (z14 << 1) + (d & M);      zz[zzOff + 14] = (int)c;  c >>>= 32;
        c += d >>> 32;                  zz[zzOff + 15] = (int)c;
        zz[zzOff + 16] = 0;
    }

    /**
     * zz = x R, the wide value that stands for the element x: its limbs from eight x's, and the rest
     * 0. It is added into a sum of products where the formula adds an element itself.
     */
    static void toWide(int[] x, int xOff, int[] zz, int zzOff)
    {
        Nat.zero(SIZE, zz, zzOff);
        System.arraycopy(x, xOff, zz, zzOff + SIZE, SIZE);
        zz[zzOff + 2 * SIZE] = 0;
    }

    /**
     * zz = a x + b y, for wide values x and y in t and small integers a and b: the terms' limbs, times
     * their coefficients, added into a running sum a limb at a time, whose carry, which can be
     * negative, is shifted down arithmetically, and the signed top limbs added in last. zz may be x
     * or y.
     */
    static void combine(int[] t, int xOff, long a, int yOff, long b, int[] zz, int zzOff)
    {
        long c = 0;
        for (int i = 0; i < 2 * SIZE; ++i)
        {
            c += a * (t[xOff + i] & M) + b * (t[yOff + i] & M);
            zz[zzOff + i] = (int)c;
            c >>= 32;
        }
        zz[zzOff + 2 * SIZE] = (int)(c + a * t[xOff + 2 * SIZE] + b * t[yOff + 2 * SIZE]);
    }

    /**
     * zz = a x, for a wide value x in t and a small integer a, as the two-term {@link #combine} forms
     * its sum. zz may be x.
     */
    static void combine(int[] t, int xOff, long a, int[] zz, int zzOff)
    {
        long c = 0;
        for (int i = 0; i < 2 * SIZE; ++i)
        {
            c += a * (t[xOff + i] & M);
            zz[zzOff + i] = (int)c;
            c >>= 32;
        }
        zz[zzOff + 2 * SIZE] = (int)(c + a * t[xOff + 2 * SIZE]);
    }

    /**
     * zz = a x + b y + c w, for wide values x, y and w in t, as the two-term {@link #combine} forms its
     * sum.
     */
    static void combine(int[] t, int xOff, long a, int yOff, long b, int wOff, long c, int[] zz, int zzOff)
    {
        long s = 0;
        for (int i = 0; i < 2 * SIZE; ++i)
        {
            s += a * (t[xOff + i] & M) + b * (t[yOff + i] & M) + c * (t[wOff + i] & M);
            zz[zzOff + i] = (int)s;
            s >>= 32;
        }
        zz[zzOff + 2 * SIZE] = (int)(s + a * t[xOff + 2 * SIZE] + b * t[yOff + 2 * SIZE] + c * t[wOff + 2 * SIZE]);
    }

    /**
     * zz = a x + b y + c w + d v, for wide values x, y, w and v in t, as the two-term {@link #combine}
     * forms its sum.
     */
    static void combine(int[] t, int xOff, long a, int yOff, long b, int wOff, long c, int vOff, long d, int[] zz,
        int zzOff)
    {
        long s = 0;
        for (int i = 0; i < 2 * SIZE; ++i)
        {
            s += a * (t[xOff + i] & M) + b * (t[yOff + i] & M) + c * (t[wOff + i] & M) + d * (t[vOff + i] & M);
            zz[zzOff + i] = (int)s;
            s >>= 32;
        }
        zz[zzOff + 2 * SIZE] = (int)(s + a * t[xOff + 2 * SIZE] + b * t[yOff + 2 * SIZE] + c * t[wOff + 2 * SIZE]
            + d * t[vOff + 2 * SIZE]);
    }

    /**
     * zz = a x + b y + c w + d v + e u, for wide values x, y, w, v and u in t, as the two-term
     * {@link #combine} forms its sum.
     */
    static void combine(int[] t, int xOff, long a, int yOff, long b, int wOff, long c, int vOff, long d,
        int uOff, long e, int[] zz, int zzOff)
    {
        long s = 0;
        for (int i = 0; i < 2 * SIZE; ++i)
        {
            s += a * (t[xOff + i] & M) + b * (t[yOff + i] & M) + c * (t[wOff + i] & M) + d * (t[vOff + i] & M)
                + e * (t[uOff + i] & M);
            zz[zzOff + i] = (int)s;
            s >>= 32;
        }
        zz[zzOff + 2 * SIZE] = (int)(s + a * t[xOff + 2 * SIZE] + b * t[yOff + 2 * SIZE] + c * t[wOff + 2 * SIZE]
            + d * t[vOff + 2 * SIZE] + e * t[uOff + 2 * SIZE]);
    }

    /**
     * z = xx R^-1 mod q, below q, for a wide value xx below 2^520 in magnitude: the element xx stands
     * for, in the form the other methods compute on.
     * <p>
     * Montgomery's reduction takes xx to xx_1 + t, for xx_1 the limbs of xx from eight, signed, and
     * t = (xx_0 + m q) / R, xx_0 being its low eight limbs and m the integer below R for which
     * xx_0 + m q is a multiple of R: t lies in [0, q], and xx_1 + t = (xx + m q) / R, which is
     * congruent to xx R^-1 mod q. The rounds that form t are {@link #mul}'s, without its products
     * x_i y.
     * <p>
     * u = xx_1 + t + 512 q, congruent to it, then lies between 108 2^256 and 622 2^256, and so above 0,
     * and is brought below q through its top sixty-four bits h, below 2^42: for q_7 the top limb of
     * q, h floor(2^52 / (q_7 + 1)) / 2^52 is at most u / q, since h 2^224 &lt;= u and
     * q &lt; (q_7 + 1) 2^224, and within 2^-10 of it, so that k, its floor, is floor(u / q) or one less,
     * and u - k q lies in [0, 2q). u - k q and u - (k + 1) q are formed side by side, and one kept under
     * a mask taken from the sign of the second, as the other operations keep a sum or its difference
     * less q: the same instructions whatever xx is.
     */
    static void reduceWide(int[] xx, int xxOff, int[] z, int zOff)
    {
        long t0 = xx[xxOff] & M, t1 = xx[xxOff + 1] & M, t2 = xx[xxOff + 2] & M, t3 = xx[xxOff + 3] & M;
        long t4 = xx[xxOff + 4] & M, t5 = xx[xxOff + 5] & M, t6 = xx[xxOff + 6] & M, t7 = xx[xxOff + 7] & M;
        for (int i = 0; i < SIZE; ++i)
        {
            long m = (t0 * N0) & M;
            long c = (t0 + m * Q0) >>> 32;
            c += t1 + m * Q1;           t0 = c & M; c >>>= 32;
            c += t2 + m * Q2;           t1 = c & M; c >>>= 32;
            c += t3 + m * Q3;           t2 = c & M; c >>>= 32;
            c += t4 + m * Q4;           t3 = c & M; c >>>= 32;
            c += t5 + m * Q5;           t4 = c & M; c >>>= 32;
            c += t6 + m * Q6;           t5 = c & M; c >>>= 32;
            c += t7 + m * Q7;           t6 = c & M; c >>>= 32;
            t7 = c;
        }

        // u = xx_1 + t + 512 q
        long c = (xx[xxOff + 8] & M) + t0 + O0;        long u0 = c & M;    c >>>= 32;
        c += (xx[xxOff + 9] & M) + t1 + O1;            long u1 = c & M;    c >>>= 32;
        c += (xx[xxOff + 10] & M) + t2 + O2;           long u2 = c & M;    c >>>= 32;
        c += (xx[xxOff + 11] & M) + t3 + O3;           long u3 = c & M;    c >>>= 32;
        c += (xx[xxOff + 12] & M) + t4 + O4;           long u4 = c & M;    c >>>= 32;
        c += (xx[xxOff + 13] & M) + t5 + O5;           long u5 = c & M;    c >>>= 32;
        c += (xx[xxOff + 14] & M) + t6 + O6;           long u6 = c & M;    c >>>= 32;
        c += (xx[xxOff + 15] & M) + t7 + O7;           long u7 = c & M;    c >>>= 32;
        long u8 = c + xx[xxOff + 16] + O8;

        // u - k q into v, and u - (k + 1) q into d
        long k = (((u8 << 32) | u7) * QUOTIENT) >>> 52;
        long v = u0 - k * Q0, d = v - Q0;           long v0 = v & M, d0 = d & M;    v >>= 32; d >>= 32;
        long p = u1 - k * Q1;   v += p; d += p - Q1;    long v1 = v & M, d1 = d & M;    v >>= 32; d >>= 32;
        p = u2 - k * Q2;        v += p; d += p - Q2;    long v2 = v & M, d2 = d & M;    v >>= 32; d >>= 32;
        p = u3 - k * Q3;        v += p; d += p - Q3;    long v3 = v & M, d3 = d & M;    v >>= 32; d >>= 32;
        p = u4 - k * Q4;        v += p; d += p - Q4;    long v4 = v & M, d4 = d & M;    v >>= 32; d >>= 32;
        p = u5 - k * Q5;        v += p; d += p - Q5;    long v5 = v & M, d5 = d & M;    v >>= 32; d >>= 32;
        p = u6 - k * Q6;        v += p; d += p - Q6;    long v6 = v & M, d6 = d & M;    v >>= 32; d >>= 32;
        p = u7 - k * Q7;        v += p; d += p - Q7;    long v7 = v & M, d7 = d & M;    d >>= 32;

        // d + u8 is -1 if u - k q is below q, and 0 if not: u - k q is kept under it, and u - (k + 1) q
        // under its complement
        d += u8;
        z[zOff] = (int)((v0 & d) | (d0 & ~d));
        z[zOff + 1] = (int)((v1 & d) | (d1 & ~d));
        z[zOff + 2] = (int)((v2 & d) | (d2 & ~d));
        z[zOff + 3] = (int)((v3 & d) | (d3 & ~d));
        z[zOff + 4] = (int)((v4 & d) | (d4 & ~d));
        z[zOff + 5] = (int)((v5 & d) | (d5 & ~d));
        z[zOff + 6] = (int)((v6 & d) | (d6 & ~d));
        z[zOff + 7] = (int)((v7 & d) | (d7 & ~d));
    }

    /**
     * z = x^-1, for x other than 0. For x in Montgomery form, x R, BouncyCastle's constant-time
     * {@link Mod#checkedModOddInverse} gives the integer (x R)^-1 = x^-1 R^-1 mod q, and its Montgomery
     * product with R^3 is x^-1 R. An x of 0 is refused with an ArithmeticException, as
     * SM9P256V1Field's inversion refuses it, rather than answered with 0.
     */
    static void inv(int[] x, int xOff, int[] z, int zOff)
    {
        int[] t = new int[SIZE];
        try
        {
            System.arraycopy(x, xOff, t, 0, SIZE);
            Mod.checkedModOddInverse(P, t, t);
            mul(t, 0, R3, 0, z, zOff);
        }
        finally
        {
            Arrays.clear(t);
        }
    }

    /**
     * Exchanges the limbs of x and y, which are the same length, when swap is 1 and leaves them when
     * it is 0, reading and writing both whichever it is: the conditional exchange a ladder makes on
     * each bit of a secret, without a branch on the bit.
     */
    static void cswap(int swap, int[] x, int[] y)
    {
        int mask = -swap;
        for (int i = 0; i < x.length; ++i)
        {
            int d = mask & (x[i] ^ y[i]);
            x[i] ^= d;
            y[i] ^= d;
        }
    }

    static boolean isZero(int[] x, int xOff)
    {
        int d = 0;
        for (int i = 0; i < SIZE; ++i)
        {
            d |= x[xOff + i];
        }
        return d == 0;
    }

    /**
     * The value x stands for, out of Montgomery form by its Montgomery product with 1, as 32
     * big-endian bytes from off.
     */
    static void encode(int[] x, int xOff, byte[] buf, int off)
    {
        int[] t = new int[SIZE];
        mul(x, xOff, UNIT, 0, t, 0);
        for (int i = 0; i < SIZE; ++i)
        {
            Pack.intToBigEndian(t[SIZE - 1 - i], buf, off + 4 * i);
        }
        Arrays.clear(t);
    }

    /**
     * The element whose value is the 32 big-endian bytes from off, into z, and whether that value is
     * below q; z is not an element of the field when it is not.
     */
    static boolean decode(byte[] buf, int off, int[] z, int zOff)
    {
        int[] t = new int[SIZE];
        for (int i = 0; i < SIZE; ++i)
        {
            t[SIZE - 1 - i] = Pack.bigEndianToInt(buf, off + 4 * i);
        }
        boolean below = isBelowQ(t, 0);
        mul(t, 0, R2, 0, z, zOff);
        Arrays.clear(t);
        return below;
    }

    /**
     * The element x mod q stands for, into z, for x a public value: a constant, or a coordinate of a
     * point anyone may see.
     */
    static void fromBigInteger(BigInteger x, int[] z, int zOff)
    {
        decode(BigIntegers.asUnsignedByteArray(32, x.mod(Q)), 0, z, zOff);
    }

    // the draws random and randomNonZero make before they fail, as the draws of the nonce and the keys
    // do: a source that yields nothing usable - only zeros, or only ones - would otherwise keep them
    // drawing without end, and settling for a value that can always be given, as
    // BigIntegers.createRandomInRange, which they replace, does, would give every call the same value
    // and so undo the randomisation it is drawn for without a sign of it
    private static final int MAX_DRAWS = 1000;

    /**
     * A uniformly random element, into z: eight limbs drawn until they are below q, and taken as the
     * Montgomery form of an element - a bijection on [0, q), so a uniform draw is a uniform element.
     * q is a little over 2^255.5, so that takes under 1.5 draws on average; if none of
     * {@link #MAX_DRAWS} draws is below q, it throws IllegalStateException.
     */
    static void random(SecureRandom random, int[] z, int zOff)
    {
        byte[] b = new byte[4 * SIZE];
        for (int i = 0; i < MAX_DRAWS; ++i)
        {
            random.nextBytes(b);
            Pack.littleEndianToInt(b, 0, z, zOff, SIZE);
            if (isBelowQ(z, zOff))
            {
                Arrays.clear(b);
                return;
            }
        }
        Arrays.clear(b);
        throw new IllegalStateException("SM9 arithmetic could not draw a usable random element");
    }

    /**
     * A uniformly random element other than 0, as {@link #random} draws them; if none of
     * {@link #MAX_DRAWS} of them is other than 0, it throws IllegalStateException.
     */
    static void randomNonZero(SecureRandom random, int[] z, int zOff)
    {
        for (int i = 0; i < MAX_DRAWS; ++i)
        {
            random(random, z, zOff);
            if (!isZero(z, zOff))
            {
                return;
            }
        }
        throw new IllegalStateException("SM9 arithmetic could not draw a usable random element");
    }

    // whether x, as eight limbs, is below q: the borrow out of x - q
    private static boolean isBelowQ(int[] x, int xOff)
    {
        long b = (x[xOff] & M) - Q0;            b >>= 32;
        b += (x[xOff + 1] & M) - Q1;            b >>= 32;
        b += (x[xOff + 2] & M) - Q2;            b >>= 32;
        b += (x[xOff + 3] & M) - Q3;            b >>= 32;
        b += (x[xOff + 4] & M) - Q4;            b >>= 32;
        b += (x[xOff + 5] & M) - Q5;            b >>= 32;
        b += (x[xOff + 6] & M) - Q6;            b >>= 32;
        b += (x[xOff + 7] & M) - Q7;            b >>= 32;
        return b != 0;
    }

    // z = t - q if t, given as nine limbs, is at least q, and t if it is not; t is below 2q
    private static void reduce(long t0, long t1, long t2, long t3, long t4, long t5, long t6, long t7,
        long t8, int[] z, int zOff)
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
        z[zOff] = (int)((t0 & b) | (d0 & ~b));
        z[zOff + 1] = (int)((t1 & b) | (d1 & ~b));
        z[zOff + 2] = (int)((t2 & b) | (d2 & ~b));
        z[zOff + 3] = (int)((t3 & b) | (d3 & ~b));
        z[zOff + 4] = (int)((t4 & b) | (d4 & ~b));
        z[zOff + 5] = (int)((t5 & b) | (d5 & ~b));
        z[zOff + 6] = (int)((t6 & b) | (d6 & ~b));
        z[zOff + 7] = (int)((t7 & b) | (d7 & ~b));
    }

    private Fp()
    {
    }
}
