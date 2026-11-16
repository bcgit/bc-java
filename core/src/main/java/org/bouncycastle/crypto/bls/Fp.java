package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

import org.bouncycastle.math.raw.Mod;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Pack;

/**
 * Arithmetic in Fp, the base field of BLS12-381, on which {@link Fp2Element} and so the whole
 * extension tower is built. An element is held as twelve 32-bit limbs, least significant first, at
 * an offset in an int array, in Montgomery form - x R mod p for R = 2^384 - and is always fully
 * reduced, below p, so that each element has exactly one representation.
 * <p>
 * Each operation runs the same instructions whatever values it is given: no branch, early exit or
 * array index depends on them, and a result is brought below p by a subtraction of p that is always
 * made, its difference kept or discarded through a mask. The {@link BigInteger} arithmetic this
 * replaces could not give that - its running time follows the magnitude of the values - and the
 * values include intermediate points of the signing multiplication. The exceptions take public
 * values: {@link #fromBigInteger} and {@link #decode}, for constants and encoded inputs.
 * <p>
 * The products in the extension fields reduce each coefficient of their result once: they form the
 * products in Fp their formulas call for in full, as the wide values of {@link #WIDE}, add and
 * subtract those unreduced, and bring each coefficient to an element by {@link #reduceWide}. This
 * follows the field of the SM9 pairing ({@code org.bouncycastle.math.ec.sm9.Fp}), widened from eight
 * limbs to twelve.
 */
final class Fp
{
    static final int SIZE = 12;

    /** The field characteristic p. */
    static final BigInteger Q = BLS12_381G1.Q;

    private static final long M = 0xFFFFFFFFL;

    private static final int[] P = Nat.fromBigInteger(384, Q);

    // p's limbs, least significant first, and -p^-1 mod 2^32, for the Montgomery product
    private static final long Q0 = P[0] & M, Q1 = P[1] & M, Q2 = P[2] & M, Q3 = P[3] & M;
    private static final long Q4 = P[4] & M, Q5 = P[5] & M, Q6 = P[6] & M, Q7 = P[7] & M;
    private static final long Q8 = P[8] & M, Q9 = P[9] & M, Q10 = P[10] & M, Q11 = P[11] & M;
    private static final long N0 = -Mod.inverse32(P[0]) & M;

    // R^2 mod p, whose Montgomery product with x is x R; R^3 mod p, for the inverse; and 1, whose
    // Montgomery product with x R is x
    private static final int[] R2 = Nat.fromBigInteger(384, BigInteger.ONE.shiftLeft(768).mod(Q));
    private static final int[] R3 = Nat.fromBigInteger(384, BigInteger.ONE.shiftLeft(1152).mod(Q));
    private static final int[] UNIT = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    private static final int[] ZERO = new int[SIZE];

    /**
     * 1, in Montgomery form: R mod p.
     */
    static final int[] ONE = Nat.fromBigInteger(384, BigInteger.ONE.shiftLeft(384).mod(Q));

    /**
     * The number of limbs of a wide value: an integer below 2^768 in magnitude, about 97 p^2, as
     * twenty-five 32-bit limbs, least significant first, the top one signed and either 0 or -1,
     * standing for the element whose form its Montgomery reduction {@link #reduceWide} gives. The
     * product {@link #mulWide} forms of the forms of two elements x and y is congruent to x y R^2 mod
     * p, and so stands for x y, as does every sum and difference of such products - the coefficients
     * of a product or a square in the extension fields are made of a handful of them.
     */
    static final int WIDE = 2 * SIZE + 1;

    // 16 p, as thirteen limbs, which reduceWide adds to its value before it estimates the quotient,
    // and floor(2^52 / (p_11 + 1)) for p_11 the top limb of p, the constant it estimates it by
    private static final int[] Q16 = Nat.fromBigInteger(416, Q.shiftLeft(4));
    private static final long O0 = Q16[0] & M, O1 = Q16[1] & M, O2 = Q16[2] & M, O3 = Q16[3] & M;
    private static final long O4 = Q16[4] & M, O5 = Q16[5] & M, O6 = Q16[6] & M, O7 = Q16[7] & M;
    private static final long O8 = Q16[8] & M, O9 = Q16[9] & M, O10 = Q16[10] & M, O11 = Q16[11] & M;
    private static final long O12 = Q16[12] & M;
    private static final long QUOTIENT = (1L << 52) / (Q11 + 1);

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
        c += (x[xOff + 8] & M) + (y[yOff + 8] & M);         long t8 = c & M; c >>>= 32;
        c += (x[xOff + 9] & M) + (y[yOff + 9] & M);         long t9 = c & M; c >>>= 32;
        c += (x[xOff + 10] & M) + (y[yOff + 10] & M);       long t10 = c & M; c >>>= 32;
        c += (x[xOff + 11] & M) + (y[yOff + 11] & M);       long t11 = c & M; c >>>= 32;
        reduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, c, z, zOff);
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
        b += (x[xOff + 8] & M) - (y[yOff + 8] & M);         long t8 = b & M; b >>= 32;
        b += (x[xOff + 9] & M) - (y[yOff + 9] & M);         long t9 = b & M; b >>= 32;
        b += (x[xOff + 10] & M) - (y[yOff + 10] & M);       long t10 = b & M; b >>= 32;
        b += (x[xOff + 11] & M) - (y[yOff + 11] & M);       long t11 = b & M; b >>= 32;

        // b is -1 if x < y, and 0 otherwise: p is added back under it
        long c = t0 + (Q0 & b);     z[zOff] = (int)c; c >>>= 32;
        c += t1 + (Q1 & b);         z[zOff + 1] = (int)c; c >>>= 32;
        c += t2 + (Q2 & b);         z[zOff + 2] = (int)c; c >>>= 32;
        c += t3 + (Q3 & b);         z[zOff + 3] = (int)c; c >>>= 32;
        c += t4 + (Q4 & b);         z[zOff + 4] = (int)c; c >>>= 32;
        c += t5 + (Q5 & b);         z[zOff + 5] = (int)c; c >>>= 32;
        c += t6 + (Q6 & b);         z[zOff + 6] = (int)c; c >>>= 32;
        c += t7 + (Q7 & b);         z[zOff + 7] = (int)c; c >>>= 32;
        c += t8 + (Q8 & b);         z[zOff + 8] = (int)c; c >>>= 32;
        c += t9 + (Q9 & b);         z[zOff + 9] = (int)c; c >>>= 32;
        c += t10 + (Q10 & b);       z[zOff + 10] = (int)c; c >>>= 32;
        c += t11 + (Q11 & b);       z[zOff + 11] = (int)c;
    }

    static void neg(int[] x, int xOff, int[] z, int zOff)
    {
        sub(ZERO, 0, x, xOff, z, zOff);
    }

    /**
     * z = x y R^-1 mod p, the Montgomery product, which for x and y in Montgomery form is their
     * product in that form. This is Koc, Acar and Kaliski's CIOS method: for each limb x_i of x, a
     * running sum takes x_i y, then the multiple of p that makes its low limb 0, and is shifted down a
     * limb. The sum stays below 2p, so one subtraction of p leaves the result below p. z may be x or
     * y.
     */
    static void mul(int[] x, int xOff, int[] y, int yOff, int[] z, int zOff)
    {
        long y0 = y[yOff] & M, y1 = y[yOff + 1] & M, y2 = y[yOff + 2] & M, y3 = y[yOff + 3] & M;
        long y4 = y[yOff + 4] & M, y5 = y[yOff + 5] & M, y6 = y[yOff + 6] & M, y7 = y[yOff + 7] & M;
        long y8 = y[yOff + 8] & M, y9 = y[yOff + 9] & M, y10 = y[yOff + 10] & M, y11 = y[yOff + 11] & M;
        long t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0;
        long t7 = 0, t8 = 0, t9 = 0, t10 = 0, t11 = 0, t12 = 0;
        for (int i = 0; i < SIZE; ++i)
        {
            long xi = x[xOff + i] & M;
            long c = t0 + xi * y0;          t0 = c & M; c >>>= 32;
            c += t1 + xi * y1;              t1 = c & M; c >>>= 32;
            c += t2 + xi * y2;              t2 = c & M; c >>>= 32;
            c += t3 + xi * y3;              t3 = c & M; c >>>= 32;
            c += t4 + xi * y4;              t4 = c & M; c >>>= 32;
            c += t5 + xi * y5;              t5 = c & M; c >>>= 32;
            c += t6 + xi * y6;              t6 = c & M; c >>>= 32;
            c += t7 + xi * y7;              t7 = c & M; c >>>= 32;
            c += t8 + xi * y8;              t8 = c & M; c >>>= 32;
            c += t9 + xi * y9;              t9 = c & M; c >>>= 32;
            c += t10 + xi * y10;            t10 = c & M; c >>>= 32;
            c += t11 + xi * y11;            t11 = c & M; c >>>= 32;
            c += t12;                       t12 = c & M;
            long t13 = c >>> 32;

            long m = (t0 * N0) & M;
            c = (t0 + m * Q0) >>> 32;
            c += t1 + m * Q1;               t0 = c & M; c >>>= 32;
            c += t2 + m * Q2;               t1 = c & M; c >>>= 32;
            c += t3 + m * Q3;               t2 = c & M; c >>>= 32;
            c += t4 + m * Q4;               t3 = c & M; c >>>= 32;
            c += t5 + m * Q5;               t4 = c & M; c >>>= 32;
            c += t6 + m * Q6;               t5 = c & M; c >>>= 32;
            c += t7 + m * Q7;               t6 = c & M; c >>>= 32;
            c += t8 + m * Q8;               t7 = c & M; c >>>= 32;
            c += t9 + m * Q9;               t8 = c & M; c >>>= 32;
            c += t10 + m * Q10;             t9 = c & M; c >>>= 32;
            c += t11 + m * Q11;             t10 = c & M; c >>>= 32;
            c += t12;                       t11 = c & M;
            t12 = t13 + (c >>> 32);
        }
        reduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, z, zOff);
    }

    /**
     * z = x^2 R^-1 mod p, as the reduction of {@link #sqrWide}, whose seventy-eight products of limbs
     * make it cheaper than {@link #mul} of x by itself. z may be x.
     */
    static void sqr(int[] x, int xOff, int[] z, int zOff)
    {
        int[] tt = new int[WIDE];
        sqrWide(x, xOff, tt, 0);
        reduceWide(tt, 0, z, zOff);
    }

    /**
     * zz = x y in full, as a wide value - see {@link #WIDE} - below p^2 for two elements: row by row,
     * x_i y added into the limbs from i, the limbs of the sum held in locals.
     */
    static void mulWide(int[] x, int xOff, int[] y, int yOff, int[] zz, int zzOff)
    {
        long y0 = y[yOff] & M, y1 = y[yOff + 1] & M, y2 = y[yOff + 2] & M, y3 = y[yOff + 3] & M;
        long y4 = y[yOff + 4] & M, y5 = y[yOff + 5] & M, y6 = y[yOff + 6] & M, y7 = y[yOff + 7] & M;
        long y8 = y[yOff + 8] & M, y9 = y[yOff + 9] & M, y10 = y[yOff + 10] & M, y11 = y[yOff + 11] & M;

        long xi = x[xOff] & M;
        long c = xi * y0;           long z0 = c & M;   c >>>= 32;
        c += xi * y1;               long z1 = c & M;   c >>>= 32;
        c += xi * y2;               long z2 = c & M;   c >>>= 32;
        c += xi * y3;               long z3 = c & M;   c >>>= 32;
        c += xi * y4;               long z4 = c & M;   c >>>= 32;
        c += xi * y5;               long z5 = c & M;   c >>>= 32;
        c += xi * y6;               long z6 = c & M;   c >>>= 32;
        c += xi * y7;               long z7 = c & M;   c >>>= 32;
        c += xi * y8;               long z8 = c & M;   c >>>= 32;
        c += xi * y9;               long z9 = c & M;   c >>>= 32;
        c += xi * y10;              long z10 = c & M;  c >>>= 32;
        c += xi * y11;              long z11 = c & M;  c >>>= 32;
        long z12 = c;

        xi = x[xOff + 1] & M;
        c = z1 + xi * y0;           z1 = c & M;        c >>>= 32;
        c += z2 + xi * y1;          z2 = c & M;        c >>>= 32;
        c += z3 + xi * y2;          z3 = c & M;        c >>>= 32;
        c += z4 + xi * y3;          z4 = c & M;        c >>>= 32;
        c += z5 + xi * y4;          z5 = c & M;        c >>>= 32;
        c += z6 + xi * y5;          z6 = c & M;        c >>>= 32;
        c += z7 + xi * y6;          z7 = c & M;        c >>>= 32;
        c += z8 + xi * y7;          z8 = c & M;        c >>>= 32;
        c += z9 + xi * y8;          z9 = c & M;        c >>>= 32;
        c += z10 + xi * y9;         z10 = c & M;       c >>>= 32;
        c += z11 + xi * y10;        z11 = c & M;       c >>>= 32;
        c += z12 + xi * y11;        z12 = c & M;       c >>>= 32;
        long z13 = c;

        xi = x[xOff + 2] & M;
        c = z2 + xi * y0;           z2 = c & M;        c >>>= 32;
        c += z3 + xi * y1;          z3 = c & M;        c >>>= 32;
        c += z4 + xi * y2;          z4 = c & M;        c >>>= 32;
        c += z5 + xi * y3;          z5 = c & M;        c >>>= 32;
        c += z6 + xi * y4;          z6 = c & M;        c >>>= 32;
        c += z7 + xi * y5;          z7 = c & M;        c >>>= 32;
        c += z8 + xi * y6;          z8 = c & M;        c >>>= 32;
        c += z9 + xi * y7;          z9 = c & M;        c >>>= 32;
        c += z10 + xi * y8;         z10 = c & M;       c >>>= 32;
        c += z11 + xi * y9;         z11 = c & M;       c >>>= 32;
        c += z12 + xi * y10;        z12 = c & M;       c >>>= 32;
        c += z13 + xi * y11;        z13 = c & M;       c >>>= 32;
        long z14 = c;

        xi = x[xOff + 3] & M;
        c = z3 + xi * y0;           z3 = c & M;        c >>>= 32;
        c += z4 + xi * y1;          z4 = c & M;        c >>>= 32;
        c += z5 + xi * y2;          z5 = c & M;        c >>>= 32;
        c += z6 + xi * y3;          z6 = c & M;        c >>>= 32;
        c += z7 + xi * y4;          z7 = c & M;        c >>>= 32;
        c += z8 + xi * y5;          z8 = c & M;        c >>>= 32;
        c += z9 + xi * y6;          z9 = c & M;        c >>>= 32;
        c += z10 + xi * y7;         z10 = c & M;       c >>>= 32;
        c += z11 + xi * y8;         z11 = c & M;       c >>>= 32;
        c += z12 + xi * y9;         z12 = c & M;       c >>>= 32;
        c += z13 + xi * y10;        z13 = c & M;       c >>>= 32;
        c += z14 + xi * y11;        z14 = c & M;       c >>>= 32;
        long z15 = c;

        xi = x[xOff + 4] & M;
        c = z4 + xi * y0;           z4 = c & M;        c >>>= 32;
        c += z5 + xi * y1;          z5 = c & M;        c >>>= 32;
        c += z6 + xi * y2;          z6 = c & M;        c >>>= 32;
        c += z7 + xi * y3;          z7 = c & M;        c >>>= 32;
        c += z8 + xi * y4;          z8 = c & M;        c >>>= 32;
        c += z9 + xi * y5;          z9 = c & M;        c >>>= 32;
        c += z10 + xi * y6;         z10 = c & M;       c >>>= 32;
        c += z11 + xi * y7;         z11 = c & M;       c >>>= 32;
        c += z12 + xi * y8;         z12 = c & M;       c >>>= 32;
        c += z13 + xi * y9;         z13 = c & M;       c >>>= 32;
        c += z14 + xi * y10;        z14 = c & M;       c >>>= 32;
        c += z15 + xi * y11;        z15 = c & M;       c >>>= 32;
        long z16 = c;

        xi = x[xOff + 5] & M;
        c = z5 + xi * y0;           z5 = c & M;        c >>>= 32;
        c += z6 + xi * y1;          z6 = c & M;        c >>>= 32;
        c += z7 + xi * y2;          z7 = c & M;        c >>>= 32;
        c += z8 + xi * y3;          z8 = c & M;        c >>>= 32;
        c += z9 + xi * y4;          z9 = c & M;        c >>>= 32;
        c += z10 + xi * y5;         z10 = c & M;       c >>>= 32;
        c += z11 + xi * y6;         z11 = c & M;       c >>>= 32;
        c += z12 + xi * y7;         z12 = c & M;       c >>>= 32;
        c += z13 + xi * y8;         z13 = c & M;       c >>>= 32;
        c += z14 + xi * y9;         z14 = c & M;       c >>>= 32;
        c += z15 + xi * y10;        z15 = c & M;       c >>>= 32;
        c += z16 + xi * y11;        z16 = c & M;       c >>>= 32;
        long z17 = c;

        xi = x[xOff + 6] & M;
        c = z6 + xi * y0;           z6 = c & M;        c >>>= 32;
        c += z7 + xi * y1;          z7 = c & M;        c >>>= 32;
        c += z8 + xi * y2;          z8 = c & M;        c >>>= 32;
        c += z9 + xi * y3;          z9 = c & M;        c >>>= 32;
        c += z10 + xi * y4;         z10 = c & M;       c >>>= 32;
        c += z11 + xi * y5;         z11 = c & M;       c >>>= 32;
        c += z12 + xi * y6;         z12 = c & M;       c >>>= 32;
        c += z13 + xi * y7;         z13 = c & M;       c >>>= 32;
        c += z14 + xi * y8;         z14 = c & M;       c >>>= 32;
        c += z15 + xi * y9;         z15 = c & M;       c >>>= 32;
        c += z16 + xi * y10;        z16 = c & M;       c >>>= 32;
        c += z17 + xi * y11;        z17 = c & M;       c >>>= 32;
        long z18 = c;

        xi = x[xOff + 7] & M;
        c = z7 + xi * y0;           z7 = c & M;        c >>>= 32;
        c += z8 + xi * y1;          z8 = c & M;        c >>>= 32;
        c += z9 + xi * y2;          z9 = c & M;        c >>>= 32;
        c += z10 + xi * y3;         z10 = c & M;       c >>>= 32;
        c += z11 + xi * y4;         z11 = c & M;       c >>>= 32;
        c += z12 + xi * y5;         z12 = c & M;       c >>>= 32;
        c += z13 + xi * y6;         z13 = c & M;       c >>>= 32;
        c += z14 + xi * y7;         z14 = c & M;       c >>>= 32;
        c += z15 + xi * y8;         z15 = c & M;       c >>>= 32;
        c += z16 + xi * y9;         z16 = c & M;       c >>>= 32;
        c += z17 + xi * y10;        z17 = c & M;       c >>>= 32;
        c += z18 + xi * y11;        z18 = c & M;       c >>>= 32;
        long z19 = c;

        xi = x[xOff + 8] & M;
        c = z8 + xi * y0;           z8 = c & M;        c >>>= 32;
        c += z9 + xi * y1;          z9 = c & M;        c >>>= 32;
        c += z10 + xi * y2;         z10 = c & M;       c >>>= 32;
        c += z11 + xi * y3;         z11 = c & M;       c >>>= 32;
        c += z12 + xi * y4;         z12 = c & M;       c >>>= 32;
        c += z13 + xi * y5;         z13 = c & M;       c >>>= 32;
        c += z14 + xi * y6;         z14 = c & M;       c >>>= 32;
        c += z15 + xi * y7;         z15 = c & M;       c >>>= 32;
        c += z16 + xi * y8;         z16 = c & M;       c >>>= 32;
        c += z17 + xi * y9;         z17 = c & M;       c >>>= 32;
        c += z18 + xi * y10;        z18 = c & M;       c >>>= 32;
        c += z19 + xi * y11;        z19 = c & M;       c >>>= 32;
        long z20 = c;

        xi = x[xOff + 9] & M;
        c = z9 + xi * y0;           z9 = c & M;        c >>>= 32;
        c += z10 + xi * y1;         z10 = c & M;       c >>>= 32;
        c += z11 + xi * y2;         z11 = c & M;       c >>>= 32;
        c += z12 + xi * y3;         z12 = c & M;       c >>>= 32;
        c += z13 + xi * y4;         z13 = c & M;       c >>>= 32;
        c += z14 + xi * y5;         z14 = c & M;       c >>>= 32;
        c += z15 + xi * y6;         z15 = c & M;       c >>>= 32;
        c += z16 + xi * y7;         z16 = c & M;       c >>>= 32;
        c += z17 + xi * y8;         z17 = c & M;       c >>>= 32;
        c += z18 + xi * y9;         z18 = c & M;       c >>>= 32;
        c += z19 + xi * y10;        z19 = c & M;       c >>>= 32;
        c += z20 + xi * y11;        z20 = c & M;       c >>>= 32;
        long z21 = c;

        xi = x[xOff + 10] & M;
        c = z10 + xi * y0;          z10 = c & M;       c >>>= 32;
        c += z11 + xi * y1;         z11 = c & M;       c >>>= 32;
        c += z12 + xi * y2;         z12 = c & M;       c >>>= 32;
        c += z13 + xi * y3;         z13 = c & M;       c >>>= 32;
        c += z14 + xi * y4;         z14 = c & M;       c >>>= 32;
        c += z15 + xi * y5;         z15 = c & M;       c >>>= 32;
        c += z16 + xi * y6;         z16 = c & M;       c >>>= 32;
        c += z17 + xi * y7;         z17 = c & M;       c >>>= 32;
        c += z18 + xi * y8;         z18 = c & M;       c >>>= 32;
        c += z19 + xi * y9;         z19 = c & M;       c >>>= 32;
        c += z20 + xi * y10;        z20 = c & M;       c >>>= 32;
        c += z21 + xi * y11;        z21 = c & M;       c >>>= 32;
        long z22 = c;

        xi = x[xOff + 11] & M;
        c = z11 + xi * y0;          z11 = c & M;       c >>>= 32;
        c += z12 + xi * y1;         z12 = c & M;       c >>>= 32;
        c += z13 + xi * y2;         z13 = c & M;       c >>>= 32;
        c += z14 + xi * y3;         z14 = c & M;       c >>>= 32;
        c += z15 + xi * y4;         z15 = c & M;       c >>>= 32;
        c += z16 + xi * y5;         z16 = c & M;       c >>>= 32;
        c += z17 + xi * y6;         z17 = c & M;       c >>>= 32;
        c += z18 + xi * y7;         z18 = c & M;       c >>>= 32;
        c += z19 + xi * y8;         z19 = c & M;       c >>>= 32;
        c += z20 + xi * y9;         z20 = c & M;       c >>>= 32;
        c += z21 + xi * y10;        z21 = c & M;       c >>>= 32;
        c += z22 + xi * y11;        z22 = c & M;       c >>>= 32;
        long z23 = c;

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
        zz[zzOff + 16] = (int)z16;
        zz[zzOff + 17] = (int)z17;
        zz[zzOff + 18] = (int)z18;
        zz[zzOff + 19] = (int)z19;
        zz[zzOff + 20] = (int)z20;
        zz[zzOff + 21] = (int)z21;
        zz[zzOff + 22] = (int)z22;
        zz[zzOff + 23] = (int)z23;
        zz[zzOff + 24] = 0;
    }

    /**
     * zz = x^2 in full, as a wide value, as {@link #mulWide} forms x x: the products x_i x_j for
     * i &lt; j, twice their sum, and the squares x_i^2 - seventy-eight products of limbs where mulWide
     * takes a hundred and forty-four.
     */
    static void sqrWide(int[] x, int xOff, int[] zz, int zzOff)
    {
        long x0 = x[xOff] & M, x1 = x[xOff + 1] & M, x2 = x[xOff + 2] & M, x3 = x[xOff + 3] & M;
        long x4 = x[xOff + 4] & M, x5 = x[xOff + 5] & M, x6 = x[xOff + 6] & M, x7 = x[xOff + 7] & M;
        long x8 = x[xOff + 8] & M, x9 = x[xOff + 9] & M, x10 = x[xOff + 10] & M, x11 = x[xOff + 11] & M;

        // the products x_i x_j for i < j, a row for each i
        long c = x0 * x1;           long z1 = c & M;   c >>>= 32;
        c += x0 * x2;               long z2 = c & M;   c >>>= 32;
        c += x0 * x3;               long z3 = c & M;   c >>>= 32;
        c += x0 * x4;               long z4 = c & M;   c >>>= 32;
        c += x0 * x5;               long z5 = c & M;   c >>>= 32;
        c += x0 * x6;               long z6 = c & M;   c >>>= 32;
        c += x0 * x7;               long z7 = c & M;   c >>>= 32;
        c += x0 * x8;               long z8 = c & M;   c >>>= 32;
        c += x0 * x9;               long z9 = c & M;   c >>>= 32;
        c += x0 * x10;              long z10 = c & M;  c >>>= 32;
        c += x0 * x11;              long z11 = c & M;  c >>>= 32;
        long z12 = c;

        c = z3 + x1 * x2;           z3 = c & M;        c >>>= 32;
        c += z4 + x1 * x3;          z4 = c & M;        c >>>= 32;
        c += z5 + x1 * x4;          z5 = c & M;        c >>>= 32;
        c += z6 + x1 * x5;          z6 = c & M;        c >>>= 32;
        c += z7 + x1 * x6;          z7 = c & M;        c >>>= 32;
        c += z8 + x1 * x7;          z8 = c & M;        c >>>= 32;
        c += z9 + x1 * x8;          z9 = c & M;        c >>>= 32;
        c += z10 + x1 * x9;         z10 = c & M;       c >>>= 32;
        c += z11 + x1 * x10;        z11 = c & M;       c >>>= 32;
        c += z12 + x1 * x11;        z12 = c & M;       c >>>= 32;
        long z13 = c;

        c = z5 + x2 * x3;           z5 = c & M;        c >>>= 32;
        c += z6 + x2 * x4;          z6 = c & M;        c >>>= 32;
        c += z7 + x2 * x5;          z7 = c & M;        c >>>= 32;
        c += z8 + x2 * x6;          z8 = c & M;        c >>>= 32;
        c += z9 + x2 * x7;          z9 = c & M;        c >>>= 32;
        c += z10 + x2 * x8;         z10 = c & M;       c >>>= 32;
        c += z11 + x2 * x9;         z11 = c & M;       c >>>= 32;
        c += z12 + x2 * x10;        z12 = c & M;       c >>>= 32;
        c += z13 + x2 * x11;        z13 = c & M;       c >>>= 32;
        long z14 = c;

        c = z7 + x3 * x4;           z7 = c & M;        c >>>= 32;
        c += z8 + x3 * x5;          z8 = c & M;        c >>>= 32;
        c += z9 + x3 * x6;          z9 = c & M;        c >>>= 32;
        c += z10 + x3 * x7;         z10 = c & M;       c >>>= 32;
        c += z11 + x3 * x8;         z11 = c & M;       c >>>= 32;
        c += z12 + x3 * x9;         z12 = c & M;       c >>>= 32;
        c += z13 + x3 * x10;        z13 = c & M;       c >>>= 32;
        c += z14 + x3 * x11;        z14 = c & M;       c >>>= 32;
        long z15 = c;

        c = z9 + x4 * x5;           z9 = c & M;        c >>>= 32;
        c += z10 + x4 * x6;         z10 = c & M;       c >>>= 32;
        c += z11 + x4 * x7;         z11 = c & M;       c >>>= 32;
        c += z12 + x4 * x8;         z12 = c & M;       c >>>= 32;
        c += z13 + x4 * x9;         z13 = c & M;       c >>>= 32;
        c += z14 + x4 * x10;        z14 = c & M;       c >>>= 32;
        c += z15 + x4 * x11;        z15 = c & M;       c >>>= 32;
        long z16 = c;

        c = z11 + x5 * x6;          z11 = c & M;       c >>>= 32;
        c += z12 + x5 * x7;         z12 = c & M;       c >>>= 32;
        c += z13 + x5 * x8;         z13 = c & M;       c >>>= 32;
        c += z14 + x5 * x9;         z14 = c & M;       c >>>= 32;
        c += z15 + x5 * x10;        z15 = c & M;       c >>>= 32;
        c += z16 + x5 * x11;        z16 = c & M;       c >>>= 32;
        long z17 = c;

        c = z13 + x6 * x7;          z13 = c & M;       c >>>= 32;
        c += z14 + x6 * x8;         z14 = c & M;       c >>>= 32;
        c += z15 + x6 * x9;         z15 = c & M;       c >>>= 32;
        c += z16 + x6 * x10;        z16 = c & M;       c >>>= 32;
        c += z17 + x6 * x11;        z17 = c & M;       c >>>= 32;
        long z18 = c;

        c = z15 + x7 * x8;          z15 = c & M;       c >>>= 32;
        c += z16 + x7 * x9;         z16 = c & M;       c >>>= 32;
        c += z17 + x7 * x10;        z17 = c & M;       c >>>= 32;
        c += z18 + x7 * x11;        z18 = c & M;       c >>>= 32;
        long z19 = c;

        c = z17 + x8 * x9;          z17 = c & M;       c >>>= 32;
        c += z18 + x8 * x10;        z18 = c & M;       c >>>= 32;
        c += z19 + x8 * x11;        z19 = c & M;       c >>>= 32;
        long z20 = c;

        c = z19 + x9 * x10;         z19 = c & M;       c >>>= 32;
        c += z20 + x9 * x11;        z20 = c & M;       c >>>= 32;
        long z21 = c;

        c = z21 + x10 * x11;        z21 = c & M;       c >>>= 32;
        long z22 = c;

        // twice their sum, and the squares x_i^2
        long d = x0 * x0;
        c = d & M;                          zz[zzOff] = (int)c; c >>>= 32;
        c += (z1 << 1) + (d >>> 32);        zz[zzOff + 1] = (int)c; c >>>= 32;
        d = x1 * x1;
        c += (z2 << 1) + (d & M);           zz[zzOff + 2] = (int)c; c >>>= 32;
        c += (z3 << 1) + (d >>> 32);        zz[zzOff + 3] = (int)c; c >>>= 32;
        d = x2 * x2;
        c += (z4 << 1) + (d & M);           zz[zzOff + 4] = (int)c; c >>>= 32;
        c += (z5 << 1) + (d >>> 32);        zz[zzOff + 5] = (int)c; c >>>= 32;
        d = x3 * x3;
        c += (z6 << 1) + (d & M);           zz[zzOff + 6] = (int)c; c >>>= 32;
        c += (z7 << 1) + (d >>> 32);        zz[zzOff + 7] = (int)c; c >>>= 32;
        d = x4 * x4;
        c += (z8 << 1) + (d & M);           zz[zzOff + 8] = (int)c; c >>>= 32;
        c += (z9 << 1) + (d >>> 32);        zz[zzOff + 9] = (int)c; c >>>= 32;
        d = x5 * x5;
        c += (z10 << 1) + (d & M);          zz[zzOff + 10] = (int)c; c >>>= 32;
        c += (z11 << 1) + (d >>> 32);       zz[zzOff + 11] = (int)c; c >>>= 32;
        d = x6 * x6;
        c += (z12 << 1) + (d & M);          zz[zzOff + 12] = (int)c; c >>>= 32;
        c += (z13 << 1) + (d >>> 32);       zz[zzOff + 13] = (int)c; c >>>= 32;
        d = x7 * x7;
        c += (z14 << 1) + (d & M);          zz[zzOff + 14] = (int)c; c >>>= 32;
        c += (z15 << 1) + (d >>> 32);       zz[zzOff + 15] = (int)c; c >>>= 32;
        d = x8 * x8;
        c += (z16 << 1) + (d & M);          zz[zzOff + 16] = (int)c; c >>>= 32;
        c += (z17 << 1) + (d >>> 32);       zz[zzOff + 17] = (int)c; c >>>= 32;
        d = x9 * x9;
        c += (z18 << 1) + (d & M);          zz[zzOff + 18] = (int)c; c >>>= 32;
        c += (z19 << 1) + (d >>> 32);       zz[zzOff + 19] = (int)c; c >>>= 32;
        d = x10 * x10;
        c += (z20 << 1) + (d & M);          zz[zzOff + 20] = (int)c; c >>>= 32;
        c += (z21 << 1) + (d >>> 32);       zz[zzOff + 21] = (int)c; c >>>= 32;
        d = x11 * x11;
        c += (z22 << 1) + (d & M);          zz[zzOff + 22] = (int)c; c >>>= 32;
        c += d >>> 32;                      zz[zzOff + 23] = (int)c;
        zz[zzOff + 24] = 0;
    }

    /**
     * z = x + y, for wide values: the limbs added with their carry, the signed top limbs last. z may
     * be x or y.
     */
    static void addWide(int[] x, int xOff, int[] y, int yOff, int[] zz, int zzOff)
    {
        long c = 0;
        for (int i = 0; i < 2 * SIZE; ++i)
        {
            c += (x[xOff + i] & M) + (y[yOff + i] & M);
            zz[zzOff + i] = (int)c;
            c >>= 32;
        }
        zz[zzOff + 2 * SIZE] = (int)(c + x[xOff + 2 * SIZE] + y[yOff + 2 * SIZE]);
    }

    /**
     * z = x - y, for wide values, as {@link #addWide} forms a sum, the borrow shifted down
     * arithmetically. z may be x or y.
     */
    static void subWide(int[] x, int xOff, int[] y, int yOff, int[] zz, int zzOff)
    {
        long c = 0;
        for (int i = 0; i < 2 * SIZE; ++i)
        {
            c += (x[xOff + i] & M) - (y[yOff + i] & M);
            zz[zzOff + i] = (int)c;
            c >>= 32;
        }
        zz[zzOff + 2 * SIZE] = (int)(c + x[xOff + 2 * SIZE] - y[yOff + 2 * SIZE]);
    }

    /**
     * z = x - y - w, for wide values, in one pass. z may be x, y or w.
     */
    static void subWide2(int[] x, int xOff, int[] y, int yOff, int[] w, int wOff, int[] zz, int zzOff)
    {
        long c = 0;
        for (int i = 0; i < 2 * SIZE; ++i)
        {
            c += (x[xOff + i] & M) - (y[yOff + i] & M) - (w[wOff + i] & M);
            zz[zzOff + i] = (int)c;
            c >>= 32;
        }
        zz[zzOff + 2 * SIZE] = (int)(c + x[xOff + 2 * SIZE] - y[yOff + 2 * SIZE] - w[wOff + 2 * SIZE]);
    }

    /**
     * z = xx R^-1 mod p, below p, for a wide value xx below 2^768 in magnitude: the element xx stands
     * for, in the form the other methods compute on. A wide value outside that bound, which no formula
     * of the tower forms, is refused with an IllegalStateException rather than reduced wrongly; whether
     * it is in bound depends only on how many products a formula adds, never on their values.
     * <p>
     * Montgomery's reduction takes xx to xx_1 + t, for xx_1 the limbs of xx from twelve, signed, and
     * t = (xx_0 + m p) / R, xx_0 being its low twelve limbs and m the integer below R for which
     * xx_0 + m p is a multiple of R: t lies in [0, p], and xx_1 + t = (xx + m p) / R, which is
     * congruent to xx R^-1 mod p. The rounds that form t are {@link #mul}'s, without its products
     * x_i y.
     * <p>
     * u = xx_1 + t + 16 p, congruent to it, then lies between 6 p and 27 p, as |xx_1| &lt;= 2^384 and
     * 2^384 &lt; 9.82 p, and is brought below p through its top sixty-four bits h, below 2^34: for
     * p_11 the top limb of p, h floor(2^52 / (p_11 + 1)) / 2^52 is at most u / p, since
     * h 2^352 &lt;= u and p &lt; (p_11 + 1) 2^352, and within 2^-17 of it, so that k, its floor, is
     * floor(u / p) or one less, and u - k p lies in [0, 2p). u - k p and u - (k + 1) p are formed side
     * by side, and one kept under a mask taken from the sign of the second, as the other operations
     * keep a sum or its difference less p: the same instructions whatever xx is.
     */
    static void reduceWide(int[] xx, int xxOff, int[] z, int zOff)
    {
        int top = xx[xxOff + 2 * SIZE];
        if ((top >> 31) != top)
        {
            throw new IllegalStateException("wide value out of range");
        }

        long t0 = xx[xxOff] & M, t1 = xx[xxOff + 1] & M, t2 = xx[xxOff + 2] & M, t3 = xx[xxOff + 3] & M;
        long t4 = xx[xxOff + 4] & M, t5 = xx[xxOff + 5] & M, t6 = xx[xxOff + 6] & M, t7 = xx[xxOff + 7] & M;
        long t8 = xx[xxOff + 8] & M, t9 = xx[xxOff + 9] & M, t10 = xx[xxOff + 10] & M, t11 = xx[xxOff + 11] & M;
        for (int i = 0; i < SIZE; ++i)
        {
            long m = (t0 * N0) & M;
            long c = (t0 + m * Q0) >>> 32;
            c += t1 + m * Q1;               t0 = c & M; c >>>= 32;
            c += t2 + m * Q2;               t1 = c & M; c >>>= 32;
            c += t3 + m * Q3;               t2 = c & M; c >>>= 32;
            c += t4 + m * Q4;               t3 = c & M; c >>>= 32;
            c += t5 + m * Q5;               t4 = c & M; c >>>= 32;
            c += t6 + m * Q6;               t5 = c & M; c >>>= 32;
            c += t7 + m * Q7;               t6 = c & M; c >>>= 32;
            c += t8 + m * Q8;               t7 = c & M; c >>>= 32;
            c += t9 + m * Q9;               t8 = c & M; c >>>= 32;
            c += t10 + m * Q10;             t9 = c & M; c >>>= 32;
            c += t11 + m * Q11;             t10 = c & M; c >>>= 32;
            t11 = c;
        }

        // u = xx_1 + t + 16 p
        long c = (xx[xxOff + 12] & M) + t0 + O0;        long u0 = c & M;   c >>>= 32;
        c += (xx[xxOff + 13] & M) + t1 + O1;            long u1 = c & M;   c >>>= 32;
        c += (xx[xxOff + 14] & M) + t2 + O2;            long u2 = c & M;   c >>>= 32;
        c += (xx[xxOff + 15] & M) + t3 + O3;            long u3 = c & M;   c >>>= 32;
        c += (xx[xxOff + 16] & M) + t4 + O4;            long u4 = c & M;   c >>>= 32;
        c += (xx[xxOff + 17] & M) + t5 + O5;            long u5 = c & M;   c >>>= 32;
        c += (xx[xxOff + 18] & M) + t6 + O6;            long u6 = c & M;   c >>>= 32;
        c += (xx[xxOff + 19] & M) + t7 + O7;            long u7 = c & M;   c >>>= 32;
        c += (xx[xxOff + 20] & M) + t8 + O8;            long u8 = c & M;   c >>>= 32;
        c += (xx[xxOff + 21] & M) + t9 + O9;            long u9 = c & M;   c >>>= 32;
        c += (xx[xxOff + 22] & M) + t10 + O10;          long u10 = c & M;  c >>>= 32;
        c += (xx[xxOff + 23] & M) + t11 + O11;          long u11 = c & M;  c >>>= 32;
        long u12 = c + top + O12;

        // u - k p into v, and u - (k + 1) p into d
        long k = (((u12 << 32) | u11) * QUOTIENT) >>> 52;
        long v = u0 - k * Q0, d = v - Q0;               long v0 = v & M, d0 = d & M;   v >>= 32; d >>= 32;
        long p = u1 - k * Q1;   v += p; d += p - Q1;    long v1 = v & M, d1 = d & M;   v >>= 32; d >>= 32;
        p = u2 - k * Q2;        v += p; d += p - Q2;    long v2 = v & M, d2 = d & M;   v >>= 32; d >>= 32;
        p = u3 - k * Q3;        v += p; d += p - Q3;    long v3 = v & M, d3 = d & M;   v >>= 32; d >>= 32;
        p = u4 - k * Q4;        v += p; d += p - Q4;    long v4 = v & M, d4 = d & M;   v >>= 32; d >>= 32;
        p = u5 - k * Q5;        v += p; d += p - Q5;    long v5 = v & M, d5 = d & M;   v >>= 32; d >>= 32;
        p = u6 - k * Q6;        v += p; d += p - Q6;    long v6 = v & M, d6 = d & M;   v >>= 32; d >>= 32;
        p = u7 - k * Q7;        v += p; d += p - Q7;    long v7 = v & M, d7 = d & M;   v >>= 32; d >>= 32;
        p = u8 - k * Q8;        v += p; d += p - Q8;    long v8 = v & M, d8 = d & M;   v >>= 32; d >>= 32;
        p = u9 - k * Q9;        v += p; d += p - Q9;    long v9 = v & M, d9 = d & M;   v >>= 32; d >>= 32;
        p = u10 - k * Q10;      v += p; d += p - Q10;   long v10 = v & M, d10 = d & M; v >>= 32; d >>= 32;
        p = u11 - k * Q11;      v += p; d += p - Q11;   long v11 = v & M, d11 = d & M; d >>= 32;

        // d + u12 is -1 if u - k p is below p, and 0 if not: u - k p is kept under it, and u - (k + 1) p
        // under its complement
        d += u12;
        z[zOff] = (int)((v0 & d) | (d0 & ~d));
        z[zOff + 1] = (int)((v1 & d) | (d1 & ~d));
        z[zOff + 2] = (int)((v2 & d) | (d2 & ~d));
        z[zOff + 3] = (int)((v3 & d) | (d3 & ~d));
        z[zOff + 4] = (int)((v4 & d) | (d4 & ~d));
        z[zOff + 5] = (int)((v5 & d) | (d5 & ~d));
        z[zOff + 6] = (int)((v6 & d) | (d6 & ~d));
        z[zOff + 7] = (int)((v7 & d) | (d7 & ~d));
        z[zOff + 8] = (int)((v8 & d) | (d8 & ~d));
        z[zOff + 9] = (int)((v9 & d) | (d9 & ~d));
        z[zOff + 10] = (int)((v10 & d) | (d10 & ~d));
        z[zOff + 11] = (int)((v11 & d) | (d11 & ~d));
    }

    /**
     * z = x^-1, for x other than 0. For x in Montgomery form, x R, BouncyCastle's constant-time
     * {@link Mod#checkedModOddInverse} gives the integer (x R)^-1 = x^-1 R^-1 mod p, and its Montgomery
     * product with R^3 is x^-1 R. An x of 0 is refused with an ArithmeticException.
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
     * Whether x and y are the same element: their limbs are the same, as each element has one form.
     */
    static boolean eq(int[] x, int xOff, int[] y, int yOff)
    {
        int d = 0;
        for (int i = 0; i < SIZE; ++i)
        {
            d |= x[xOff + i] ^ y[yOff + i];
        }
        return d == 0;
    }

    /**
     * The value x stands for, out of Montgomery form by its Montgomery product with 1, as twelve
     * limbs into z, below p.
     */
    static void fromMont(int[] x, int xOff, int[] z, int zOff)
    {
        mul(x, xOff, UNIT, 0, z, zOff);
    }

    /**
     * The value x stands for, as 48 big-endian bytes from off.
     */
    static void encode(int[] x, int xOff, byte[] buf, int off)
    {
        int[] t = new int[SIZE];
        fromMont(x, xOff, t, 0);
        for (int i = 0; i < SIZE; ++i)
        {
            Pack.intToBigEndian(t[SIZE - 1 - i], buf, off + 4 * i);
        }
        Arrays.clear(t);
    }

    /**
     * The element whose value is the 48 big-endian bytes from off, into z, and whether that value is
     * below p; z is not an element of the field when it is not.
     */
    static boolean decode(byte[] buf, int off, int[] z, int zOff)
    {
        int[] t = new int[SIZE];
        for (int i = 0; i < SIZE; ++i)
        {
            t[SIZE - 1 - i] = Pack.bigEndianToInt(buf, off + 4 * i);
        }
        boolean below = Nat.lessThan(SIZE, t, P) != 0;
        mul(t, 0, R2, 0, z, zOff);
        Arrays.clear(t);
        return below;
    }

    /**
     * The element x mod p stands for, into z, for x a public value: a constant, or a coordinate of a
     * point anyone may see.
     */
    static void fromBigInteger(BigInteger x, int[] z, int zOff)
    {
        decode(BigIntegers.asUnsignedByteArray(48, x.mod(Q)), 0, z, zOff);
    }

    /**
     * The value x stands for, in [0, p).
     */
    static BigInteger toBigInteger(int[] x, int xOff)
    {
        byte[] b = new byte[48];
        encode(x, xOff, b, 0);
        return new BigInteger(1, b);
    }

    // z = t - p if t, given as 13 limbs, is at least p, and t if it is not; t is below 2p
    private static void reduce(long t0, long t1, long t2, long t3, long t4, long t5, long t6,
        long t7, long t8, long t9, long t10, long t11, long t12, int[] z, int zOff)
    {
        long b = t0 - Q0;           long d0 = b & M;    b >>= 32;
        b += t1 - Q1;               long d1 = b & M;    b >>= 32;
        b += t2 - Q2;               long d2 = b & M;    b >>= 32;
        b += t3 - Q3;               long d3 = b & M;    b >>= 32;
        b += t4 - Q4;               long d4 = b & M;    b >>= 32;
        b += t5 - Q5;               long d5 = b & M;    b >>= 32;
        b += t6 - Q6;               long d6 = b & M;    b >>= 32;
        b += t7 - Q7;               long d7 = b & M;    b >>= 32;
        b += t8 - Q8;               long d8 = b & M;    b >>= 32;
        b += t9 - Q9;               long d9 = b & M;    b >>= 32;
        b += t10 - Q10;             long d10 = b & M;   b >>= 32;
        b += t11 - Q11;             long d11 = b & M;   b >>= 32;

        // b + t12 is -1 if t < p, and 0 if not: t is kept under it, and t - p under its complement
        b += t12;
        z[zOff] = (int)((t0 & b) | (d0 & ~b));
        z[zOff + 1] = (int)((t1 & b) | (d1 & ~b));
        z[zOff + 2] = (int)((t2 & b) | (d2 & ~b));
        z[zOff + 3] = (int)((t3 & b) | (d3 & ~b));
        z[zOff + 4] = (int)((t4 & b) | (d4 & ~b));
        z[zOff + 5] = (int)((t5 & b) | (d5 & ~b));
        z[zOff + 6] = (int)((t6 & b) | (d6 & ~b));
        z[zOff + 7] = (int)((t7 & b) | (d7 & ~b));
        z[zOff + 8] = (int)((t8 & b) | (d8 & ~b));
        z[zOff + 9] = (int)((t9 & b) | (d9 & ~b));
        z[zOff + 10] = (int)((t10 & b) | (d10 & ~b));
        z[zOff + 11] = (int)((t11 & b) | (d11 & ~b));
    }

    private Fp()
    {
    }
}
