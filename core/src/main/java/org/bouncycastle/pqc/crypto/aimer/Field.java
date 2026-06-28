package org.bouncycastle.pqc.crypto.aimer;

abstract class Field
{
    private static final long C0 = 0x5555555555555555L;
    private static final long C1 = 0x3333333333333333L;
    private static final long C2 = 0x0F0F0F0F0F0F0F0FL;
    private static final long C3 = 0x00FF00FF00FF00FFL;
    private static final long C4 = 0x0000FFFF0000FFFFL;
    private static final long C5 = 0x00000000FFFFFFFFL;
    int AIM2_NUM_WORDS_FIELD;
    protected long[] t;
    protected long[] temp;

    /**
     * Computes the polynomial square of a 64‑bit value over GF(2)[x].
     * <p>
     * The input is treated as a polynomial of degree at most 63 with coefficients in GF(2).
     * The result is a 128‑bit polynomial (degree at most 126) represented as two 64‑bit
     * parts: the first element of the returned array is the high 64 bits, the second
     * element is the low 64 bits.
     * <p>
     * The algorithm interleaves zero bits between the bits of the input, which is
     * equivalent to squaring in the polynomial ring GF(2)[x].
     *
     * @param x the 64‑bit input value (coefficients of the polynomial, LSB = coefficient of x^0)
     */
    static void poly64_sqr_s(long[] out, int outOff, long x)
    {
        long y = x >>> 32;
        x &= C5;
        x = (x | (x << 16)) & C4;
        y = (y | (y << 16)) & C4;
        x = (x | (x << 8)) & C3;
        y = (y | (y << 8)) & C3;
        x = (x | (x << 4)) & C2;
        y = (y | (y << 4)) & C2;
        x = (x | (x << 2)) & C1;
        y = (y | (y << 2)) & C1;
        x = (x | (x << 1)) & C0;
        y = (y | (y << 1)) & C0;
        out[outOff] = x;
        out[outOff + 1] = y;
    }

    static void poly64_mul_s(long[] out, int outOff, long x0, long y0)
    {
        long x1, x2, x3, x4, x5, x6, x7;
        long y1, y2, y3, y4, y5, y6, y7;
        long f0, f1, f2, f3, f4, f5, f6, f7;
        long g0, g1, g2, g3, g4, g5, g6, g7;
        long s, t;

        // Process x0
        x1 = x0 ^ (x0 >>> 32);
        x2 = ((x0 ^ (x0 >>> 16)) & C4) | ((x1 ^ (x1 << 16)) & (C4 << 16));
        x3 = ((x0 ^ (x0 >>> 8)) & C3) | ((x1 ^ (x1 << 8)) & (C3 << 8));
        x4 = x2 ^ (x2 >>> 8);
        x5 = ((x0 ^ (x0 >>> 4)) & C2) | ((x1 ^ (x1 << 4)) & (C2 << 4));
        x6 = ((x2 ^ (x2 >>> 4)) & C2) | ((x3 ^ (x3 << 4)) & (C2 << 4));
        x7 = x4 ^ (x4 >>> 4);

        s = ((x0 >>> 2) ^ x2) & C1;
        x0 ^= s << 2;
        x2 ^= s;
        s = ((x1 >>> 2) ^ x3) & C1;
        x1 ^= s << 2;
        x3 ^= s;
        s = ((x4 >>> 2) ^ x6) & C1;
        x4 ^= s << 2;
        x6 ^= s;
        s = ((x5 >>> 2) ^ x7) & C1;
        x5 ^= s << 2;
        x7 ^= s;

        s = ((x0 >>> 1) ^ x1) & C0;
        x0 ^= s << 1;
        x1 ^= s;
        s = ((x2 >>> 1) ^ x3) & C0;
        x2 ^= s << 1;
        x3 ^= s;
        s = ((x4 >>> 1) ^ x5) & C0;
        x4 ^= s << 1;
        x5 ^= s;
        s = ((x6 >>> 1) ^ x7) & C0;
        x6 ^= s << 1;
        x7 ^= s;

        // Process y0
        y1 = y0 ^ (y0 >>> 32);
        y2 = ((y0 ^ (y0 >>> 16)) & C4) | ((y1 ^ (y1 << 16)) & (C4 << 16));
        y3 = ((y0 ^ (y0 >>> 8)) & C3) | ((y1 ^ (y1 << 8)) & (C3 << 8));
        y4 = y2 ^ (y2 >>> 8);
        y5 = ((y0 ^ (y0 >>> 4)) & C2) | ((y1 ^ (y1 << 4)) & (C2 << 4));
        y6 = ((y2 ^ (y2 >>> 4)) & C2) | ((y3 ^ (y3 << 4)) & (C2 << 4));
        y7 = y4 ^ (y4 >>> 4);

        s = ((y0 >>> 2) ^ y2) & C1;
        y0 ^= s << 2;
        y2 ^= s;
        s = ((y1 >>> 2) ^ y3) & C1;
        y1 ^= s << 2;
        y3 ^= s;
        s = ((y4 >>> 2) ^ y6) & C1;
        y4 ^= s << 2;
        y6 ^= s;
        s = ((y5 >>> 2) ^ y7) & C1;
        y5 ^= s << 2;
        y7 ^= s;

        s = ((y0 >>> 1) ^ y1) & C0;
        y0 ^= s << 1;
        y1 ^= s;
        s = ((y2 >>> 1) ^ y3) & C0;
        y2 ^= s << 1;
        y3 ^= s;
        s = ((y4 >>> 1) ^ y5) & C0;
        y4 ^= s << 1;
        y5 ^= s;
        s = ((y6 >>> 1) ^ y7) & C0;
        y6 ^= s << 1;
        y7 ^= s;

        // Multiply the transformed values
        f0 = x0 & y0;
        f1 = (x0 & y1) ^ (x1 & y0);
        f2 = (x0 & y2) ^ (x1 & y1) ^ (x2 & y0);
        f3 = (x0 & y3) ^ (x1 & y2) ^ (x2 & y1) ^ (x3 & y0);
        g0 = (x1 & y3) ^ (x2 & y2) ^ (x3 & y1);
        g1 = (x2 & y3) ^ (x3 & y2);
        g2 = x3 & y3;

        f4 = x4 & y4;
        f5 = (x4 & y5) ^ (x5 & y4);
        f6 = (x4 & y6) ^ (x5 & y5) ^ (x6 & y4);
        f7 = (x4 & y7) ^ (x5 & y6) ^ (x6 & y5) ^ (x7 & y4);
        g4 = (x5 & y7) ^ (x6 & y6) ^ (x7 & y5);
        g5 = (x6 & y7) ^ (x7 & y6);
        g6 = x7 & y7;

        // Reverse the transformation
        s = ((f0 >>> 1) ^ f1) & C0;
        f0 ^= s << 1;
        f1 ^= s;
        s = ((f2 >>> 1) ^ f3) & C0;
        f2 ^= s << 1;
        f3 ^= s;
        s = ((f0 >>> 2) ^ f2) & C1;
        f0 ^= s << 2;
        f2 ^= s;
        s = ((f1 >>> 2) ^ f3) & C1;
        f1 ^= s << 2;
        f3 ^= s;
        s = ((g0 >>> 1) ^ g1) & C0;
        g0 ^= s << 1;
        g1 ^= s;
        s = (g2 >>> 1) & C0;
        g2 ^= s << 1;
        g3 = s;
        s = ((g0 >>> 2) ^ g2) & C1;
        g0 ^= s << 2;
        g2 ^= s;
        s = ((g1 >>> 2) ^ g3) & C1;
        g1 ^= s << 2;
        g3 ^= s;

        s = ((f4 >>> 1) ^ f5) & C0;
        f4 ^= s << 1;
        f5 ^= s;
        s = ((f6 >>> 1) ^ f7) & C0;
        f6 ^= s << 1;
        f7 ^= s;
        s = ((f4 >>> 2) ^ f6) & C1;
        f4 ^= s << 2;
        f6 ^= s;
        s = ((f5 >>> 2) ^ f7) & C1;
        f5 ^= s << 2;
        f7 ^= s;
        s = ((g4 >>> 1) ^ g5) & C0;
        g4 ^= s << 1;
        g5 ^= s;
        s = (g6 >>> 1) & C0;
        g6 ^= s << 1;
        g7 = s;
        s = ((g4 >>> 2) ^ g6) & C1;
        g4 ^= s << 2;
        g6 ^= s;
        s = ((g5 >>> 2) ^ g7) & C1;
        g5 ^= s << 2;
        g7 ^= s;

        // Combine the two halves
        t = f0 ^ g0;
        f0 ^= ((f5 ^ t) & C2) << 4;
        g0 ^= (g5 ^ (t >>> 4)) & C2;
        t = f1 ^ g1;
        f1 ^= (f5 ^ (t << 4)) & (C2 << 4);
        g1 ^= ((g5 ^ t) >>> 4) & C2;
        t = f2 ^ g2;
        f2 ^= ((f6 ^ t) & C2) << 4;
        g2 ^= (g6 ^ (t >>> 4)) & C2;
        t = f3 ^ g3;
        f3 ^= (f6 ^ (t << 4)) & (C2 << 4);
        g3 ^= ((g6 ^ t) >>> 4) & C2;
        t = f4 ^ g4;
        f4 ^= ((f7 ^ t) & C2) << 4;
        g4 ^= (g7 ^ (t >>> 4)) & C2;

        t = f0 ^ g0;
        f0 ^= ((f3 ^ t) & C3) << 8;
        g0 ^= (g3 ^ (t >>> 8)) & C3;
        t = f1 ^ g1;
        f1 ^= (f3 ^ (t << 8)) & (C3 << 8);
        g1 ^= ((g3 ^ t) >>> 8) & C3;
        t = f2 ^ g2;
        f2 ^= ((f4 ^ t) & C3) << 8;
        g2 ^= (g4 ^ (t >>> 8)) & C3;

        t = f0 ^ g0;
        f0 ^= ((f2 ^ t) & C4) << 16;
        g0 ^= (g2 ^ (t >>> 16)) & C4;
        t = f1 ^ g1;
        f1 ^= (f2 ^ (t << 16)) & (C4 << 16);
        g1 ^= ((g2 ^ t) >>> 16) & C4;

        t = f0 ^ g0;
        f0 ^= ((t ^ f1) & C5) << 32;
        g0 ^= ((t >>> 32) ^ g1) & C5;

        out[outOff] = f0;
        out[outOff + 1] = g0;
        //return new long[]{g0, f0};  // [z1, z0]
    }

    static void poly64_mul_s_add(long[] out, int outOff, long x0, long y0)
    {
        long x1, x2, x3, x4, x5, x6, x7;
        long y1, y2, y3, y4, y5, y6, y7;
        long f0, f1, f2, f3, f4, f5, f6, f7;
        long g0, g1, g2, g3, g4, g5, g6, g7;
        long s, t;

        // Process x0
        x1 = x0 ^ (x0 >>> 32);
        x2 = ((x0 ^ (x0 >>> 16)) & C4) | ((x1 ^ (x1 << 16)) & (C4 << 16));
        x3 = ((x0 ^ (x0 >>> 8)) & C3) | ((x1 ^ (x1 << 8)) & (C3 << 8));
        x4 = x2 ^ (x2 >>> 8);
        x5 = ((x0 ^ (x0 >>> 4)) & C2) | ((x1 ^ (x1 << 4)) & (C2 << 4));
        x6 = ((x2 ^ (x2 >>> 4)) & C2) | ((x3 ^ (x3 << 4)) & (C2 << 4));
        x7 = x4 ^ (x4 >>> 4);

        s = ((x0 >>> 2) ^ x2) & C1;
        x0 ^= s << 2;
        x2 ^= s;
        s = ((x1 >>> 2) ^ x3) & C1;
        x1 ^= s << 2;
        x3 ^= s;
        s = ((x4 >>> 2) ^ x6) & C1;
        x4 ^= s << 2;
        x6 ^= s;
        s = ((x5 >>> 2) ^ x7) & C1;
        x5 ^= s << 2;
        x7 ^= s;

        s = ((x0 >>> 1) ^ x1) & C0;
        x0 ^= s << 1;
        x1 ^= s;
        s = ((x2 >>> 1) ^ x3) & C0;
        x2 ^= s << 1;
        x3 ^= s;
        s = ((x4 >>> 1) ^ x5) & C0;
        x4 ^= s << 1;
        x5 ^= s;
        s = ((x6 >>> 1) ^ x7) & C0;
        x6 ^= s << 1;
        x7 ^= s;

        // Process y0
        y1 = y0 ^ (y0 >>> 32);
        y2 = ((y0 ^ (y0 >>> 16)) & C4) | ((y1 ^ (y1 << 16)) & (C4 << 16));
        y3 = ((y0 ^ (y0 >>> 8)) & C3) | ((y1 ^ (y1 << 8)) & (C3 << 8));
        y4 = y2 ^ (y2 >>> 8);
        y5 = ((y0 ^ (y0 >>> 4)) & C2) | ((y1 ^ (y1 << 4)) & (C2 << 4));
        y6 = ((y2 ^ (y2 >>> 4)) & C2) | ((y3 ^ (y3 << 4)) & (C2 << 4));
        y7 = y4 ^ (y4 >>> 4);

        s = ((y0 >>> 2) ^ y2) & C1;
        y0 ^= s << 2;
        y2 ^= s;
        s = ((y1 >>> 2) ^ y3) & C1;
        y1 ^= s << 2;
        y3 ^= s;
        s = ((y4 >>> 2) ^ y6) & C1;
        y4 ^= s << 2;
        y6 ^= s;
        s = ((y5 >>> 2) ^ y7) & C1;
        y5 ^= s << 2;
        y7 ^= s;

        s = ((y0 >>> 1) ^ y1) & C0;
        y0 ^= s << 1;
        y1 ^= s;
        s = ((y2 >>> 1) ^ y3) & C0;
        y2 ^= s << 1;
        y3 ^= s;
        s = ((y4 >>> 1) ^ y5) & C0;
        y4 ^= s << 1;
        y5 ^= s;
        s = ((y6 >>> 1) ^ y7) & C0;
        y6 ^= s << 1;
        y7 ^= s;

        // Multiply the transformed values
        f0 = x0 & y0;
        f1 = (x0 & y1) ^ (x1 & y0);
        f2 = (x0 & y2) ^ (x1 & y1) ^ (x2 & y0);
        f3 = (x0 & y3) ^ (x1 & y2) ^ (x2 & y1) ^ (x3 & y0);
        g0 = (x1 & y3) ^ (x2 & y2) ^ (x3 & y1);
        g1 = (x2 & y3) ^ (x3 & y2);
        g2 = x3 & y3;

        f4 = x4 & y4;
        f5 = (x4 & y5) ^ (x5 & y4);
        f6 = (x4 & y6) ^ (x5 & y5) ^ (x6 & y4);
        f7 = (x4 & y7) ^ (x5 & y6) ^ (x6 & y5) ^ (x7 & y4);
        g4 = (x5 & y7) ^ (x6 & y6) ^ (x7 & y5);
        g5 = (x6 & y7) ^ (x7 & y6);
        g6 = x7 & y7;

        // Reverse the transformation
        s = ((f0 >>> 1) ^ f1) & C0;
        f0 ^= s << 1;
        f1 ^= s;
        s = ((f2 >>> 1) ^ f3) & C0;
        f2 ^= s << 1;
        f3 ^= s;
        s = ((f0 >>> 2) ^ f2) & C1;
        f0 ^= s << 2;
        f2 ^= s;
        s = ((f1 >>> 2) ^ f3) & C1;
        f1 ^= s << 2;
        f3 ^= s;
        s = ((g0 >>> 1) ^ g1) & C0;
        g0 ^= s << 1;
        g1 ^= s;
        s = (g2 >>> 1) & C0;
        g2 ^= s << 1;
        g3 = s;
        s = ((g0 >>> 2) ^ g2) & C1;
        g0 ^= s << 2;
        g2 ^= s;
        s = ((g1 >>> 2) ^ g3) & C1;
        g1 ^= s << 2;
        g3 ^= s;

        s = ((f4 >>> 1) ^ f5) & C0;
        f4 ^= s << 1;
        f5 ^= s;
        s = ((f6 >>> 1) ^ f7) & C0;
        f6 ^= s << 1;
        f7 ^= s;
        s = ((f4 >>> 2) ^ f6) & C1;
        f4 ^= s << 2;
        f6 ^= s;
        s = ((f5 >>> 2) ^ f7) & C1;
        f5 ^= s << 2;
        f7 ^= s;
        s = ((g4 >>> 1) ^ g5) & C0;
        g4 ^= s << 1;
        g5 ^= s;
        s = (g6 >>> 1) & C0;
        g6 ^= s << 1;
        g7 = s;
        s = ((g4 >>> 2) ^ g6) & C1;
        g4 ^= s << 2;
        g6 ^= s;
        s = ((g5 >>> 2) ^ g7) & C1;
        g5 ^= s << 2;
        g7 ^= s;

        // Combine the two halves
        t = f0 ^ g0;
        f0 ^= ((f5 ^ t) & C2) << 4;
        g0 ^= (g5 ^ (t >>> 4)) & C2;
        t = f1 ^ g1;
        f1 ^= (f5 ^ (t << 4)) & (C2 << 4);
        g1 ^= ((g5 ^ t) >>> 4) & C2;
        t = f2 ^ g2;
        f2 ^= ((f6 ^ t) & C2) << 4;
        g2 ^= (g6 ^ (t >>> 4)) & C2;
        t = f3 ^ g3;
        f3 ^= (f6 ^ (t << 4)) & (C2 << 4);
        g3 ^= ((g6 ^ t) >>> 4) & C2;
        t = f4 ^ g4;
        f4 ^= ((f7 ^ t) & C2) << 4;
        g4 ^= (g7 ^ (t >>> 4)) & C2;

        t = f0 ^ g0;
        f0 ^= ((f3 ^ t) & C3) << 8;
        g0 ^= (g3 ^ (t >>> 8)) & C3;
        t = f1 ^ g1;
        f1 ^= (f3 ^ (t << 8)) & (C3 << 8);
        g1 ^= ((g3 ^ t) >>> 8) & C3;
        t = f2 ^ g2;
        f2 ^= ((f4 ^ t) & C3) << 8;
        g2 ^= (g4 ^ (t >>> 8)) & C3;

        t = f0 ^ g0;
        f0 ^= ((f2 ^ t) & C4) << 16;
        g0 ^= (g2 ^ (t >>> 16)) & C4;
        t = f1 ^ g1;
        f1 ^= (f2 ^ (t << 16)) & (C4 << 16);
        g1 ^= ((g2 ^ t) >>> 16) & C4;

        t = f0 ^ g0;
        f0 ^= ((t ^ f1) & C5) << 32;
        g0 ^= ((t >>> 32) ^ g1) & C5;

        out[outOff] ^= f0;
        out[outOff + 1] ^= g0;
        //return new long[]{g0, f0};  // [z1, z0]
    }

    static long reduce_high_word(long temp1, long temp3, long t)
    {
        return temp1 ^ temp3 ^ ((temp3 << 7) | (t >>> 57)) ^ ((temp3 << 2) | (t >>> 62)) ^ ((temp3 << 1) | (t >>> 63));
    }

    static long reduce_low_word(long temp0, long t)
    {
        return temp0 ^ t ^ (t << 7) ^ (t << 2) ^ (t << 1);
    }

    static long reduce_high_word_256(long temp1, long temp5, long t)
    {
        return temp1 ^ temp5 ^ ((temp5 << 10) | (t >>> 54)) ^ ((temp5 << 5) | (t >>> 59)) ^ ((temp5 << 2) | (t >>> 62));
    }


    static long reduce_low_word_256(long temp0, long t)
    {
        return temp0 ^ t ^ (t << 10) ^ (t << 5) ^ (t << 2);
    }

    public abstract void GF_sqr_s(long[] c, long[] a);

    public abstract void GF_mul_s(long[] c, long[] a, long[] b);

    /**
     * Inverse Mersenne S-box with e1 = 49
     */
    public abstract void GF_exp_invmer_e_1(long[] out, long[] in);

    public abstract void GF_exp_invmer_e_2(long[] out, long[] in);

    /**
     * Mersenne exponentiation with e_star = 3
     * out = in^(2^3 - 1) = in^7
     */
    public abstract void GF_exp_mer_e_star(long[] out, long[] in);

    /**
     * GF multiplication with addition: c += a * b (schoolbook method)
     * This uses poly64_mul_s (schoolbook 64-bit multiplication)
     */
    public abstract void GF_mul_add_s(long[] c, long[] a, long[] b);

}


