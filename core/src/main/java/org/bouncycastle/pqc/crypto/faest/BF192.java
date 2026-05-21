package org.bouncycastle.pqc.crypto.faest;

import org.bouncycastle.util.Pack;

/**
 * GF(2^192) arithmetic for FAEST v2.0.
 * <p>
 * Reduction polynomial: x^192 + x^7 + x^2 + x + 1 (modulus low-word 0x87, same
 * shape as GF(2^128) but the high-bit overflow lives at bit 192). Elements are
 * stored as three 64-bit limbs little-endian: {@code limbs[off]} is bits 0..63,
 * {@code limbs[off+2]} is bits 128..191.
 * <p>
 * faest-ref source of truth: {@code fields.c} (bf192_*).
 */
final class BF192
{
    /** Reduction-polynomial low word. faest-ref: fields.c:19. */
    static final long MODULUS = (1L << 7) | (1L << 2) | (1L << 1) | 1L;

    static final int LIMBS = 3;
    static final int BYTES = 24;

    /** Precomputed alpha^1..alpha^7 for GF(2^8) embedded in GF(2^192). faest-ref: bf192_alpha. */
    static final long[][] ALPHA = {
        { 0xccc8a3d56f389763L, 0xe665d76c966ebdeaL, 0x310bc8140e6b3662L },
        { 0xb233619e7cf450bbL, 0x7bf61f19d5633f26L, 0xda933726d491db34L },
        { 0x9c6d2c13f5398a0dL, 0x8232e37706328d19L, 0x0c3b0d703c754ef6L },
        { 0xdd20747cbd2bf75dL, 0x7a5542ab0058d22eL, 0x45ec519c94bc1251L },
        { 0xd8d50ce28ace2bf8L, 0x08168cb767debe84L, 0xd67d146a4ba67045L },
        { 0x970f9c76eed5e1baL, 0xf3eaf7ae5fd72048L, 0x29a6bd5f696cea43L },
        { 0xf5945dc265068571L, 0x6019fd623906e9d3L, 0xc77c56540f87c4b0L },
    };

    private BF192()
    {
    }

    /** Write {@code ALPHA[idx]} into {@code dst[dOff..dOff+LIMBS]}. */
    static void getAlpha(long[] dst, int dOff, int idx)
    {
        dst[dOff]     = ALPHA[idx][0];
        dst[dOff + 1] = ALPHA[idx][1];
        dst[dOff + 2] = ALPHA[idx][2];
    }

    static void fromBit(long[] dst, int dOff, int bit)
    {
        dst[dOff]     = bit & 1L;
        dst[dOff + 1] = 0L;
        dst[dOff + 2] = 0L;
    }

    static void mulBit(long[] dst, int dOff, long[] a, int aOff, int bit)
    {
        long mask = -((long)bit & 1L);
        dst[dOff]     = a[aOff]     & mask;
        dst[dOff + 1] = a[aOff + 1] & mask;
        dst[dOff + 2] = a[aOff + 2] & mask;
    }

    /** Bit-vector squaring of 8 GF(2^192) elements; same coefficient pattern as {@link BF8#bits_sq}. */
    static void sqBit(long[] out, int outOff, long[] in, int inOff)
    {
        long i00 = in[inOff],      i01 = in[inOff + 1],  i02 = in[inOff + 2];
        long i10 = in[inOff + 3],  i11 = in[inOff + 4],  i12 = in[inOff + 5];
        long i20 = in[inOff + 6],  i21 = in[inOff + 7],  i22 = in[inOff + 8];
        long i30 = in[inOff + 9],  i31 = in[inOff + 10], i32 = in[inOff + 11];
        long i40 = in[inOff + 12], i41 = in[inOff + 13], i42 = in[inOff + 14];
        long i50 = in[inOff + 15], i51 = in[inOff + 16], i52 = in[inOff + 17];
        long i60 = in[inOff + 18], i61 = in[inOff + 19], i62 = in[inOff + 20];
        long i70 = in[inOff + 21], i71 = in[inOff + 22], i72 = in[inOff + 23];

        // out[0] = in[0]^in[4]^in[6]
        out[outOff]     = i00 ^ i40 ^ i60;
        out[outOff + 1] = i01 ^ i41 ^ i61;
        out[outOff + 2] = i02 ^ i42 ^ i62;
        // out[1] = in[4]^in[6]^in[7]
        out[outOff + 3] = i40 ^ i60 ^ i70;
        out[outOff + 4] = i41 ^ i61 ^ i71;
        out[outOff + 5] = i42 ^ i62 ^ i72;
        // out[2] = in[1]^in[5]
        out[outOff + 6] = i10 ^ i50;
        out[outOff + 7] = i11 ^ i51;
        out[outOff + 8] = i12 ^ i52;
        // out[3] = in[4]^in[5]^in[6]^in[7]
        out[outOff + 9]  = i40 ^ i50 ^ i60 ^ i70;
        out[outOff + 10] = i41 ^ i51 ^ i61 ^ i71;
        out[outOff + 11] = i42 ^ i52 ^ i62 ^ i72;
        // out[4] = in[2]^in[4]^in[7]
        out[outOff + 12] = i20 ^ i40 ^ i70;
        out[outOff + 13] = i21 ^ i41 ^ i71;
        out[outOff + 14] = i22 ^ i42 ^ i72;
        // out[5] = in[5]^in[6]
        out[outOff + 15] = i50 ^ i60;
        out[outOff + 16] = i51 ^ i61;
        out[outOff + 17] = i52 ^ i62;
        // out[6] = in[3]^in[5]
        out[outOff + 18] = i30 ^ i50;
        out[outOff + 19] = i31 ^ i51;
        out[outOff + 20] = i32 ^ i52;
        // out[7] = in[6]^in[7]
        out[outOff + 21] = i60 ^ i70;
        out[outOff + 22] = i61 ^ i71;
        out[outOff + 23] = i62 ^ i72;
    }

    static void byteCombine(long[] dst, int dOff, long[] x, int xOff)
    {
        long l0 = x[xOff], l1 = x[xOff + 1], l2 = x[xOff + 2];
        long[] tmp = new long[LIMBS];
        for (int i = 1; i < 8; i++)
        {
            mul(tmp, 0, x, xOff + i * LIMBS, ALPHA[i - 1], 0);
            l0 ^= tmp[0]; l1 ^= tmp[1]; l2 ^= tmp[2];
        }
        dst[dOff]     = l0;
        dst[dOff + 1] = l1;
        dst[dOff + 2] = l2;
    }

    static void byteCombineBits(long[] dst, int dOff, byte[] bits, int bitsOff)
    {
        long l0 = (bits[bitsOff] & 1L);
        long l1 = 0L;
        long l2 = 0L;
        for (int i = 1; i < 8; i++)
        {
            long mask = -((long)(bits[bitsOff + i]) & 1L);
            l0 ^= ALPHA[i - 1][0] & mask;
            l1 ^= ALPHA[i - 1][1] & mask;
            l2 ^= ALPHA[i - 1][2] & mask;
        }
        dst[dOff]     = l0;
        dst[dOff + 1] = l1;
        dst[dOff + 2] = l2;
    }

    static void byteCombineSq(long[] dst, int dOff, long[] x, int xOff)
    {
        long[] sq = new long[8 * LIMBS];
        sqBit(sq, 0, x, xOff);
        byteCombine(dst, dOff, sq, 0);
    }

    static void byteCombineBitsSq(long[] dst, int dOff, byte[] bits, int bitsOff)
    {
        byte[] y = new byte[8];
        System.arraycopy(bits, bitsOff, y, 0, 8);
        BF8.bits_sq(y);
        byteCombineBits(dst, dOff, y, 0);
    }

    static void zero(long[] dst, int off)
    {
        dst[off]     = 0L;
        dst[off + 1] = 0L;
        dst[off + 2] = 0L;
    }

    static void one(long[] dst, int off)
    {
        dst[off]     = 1L;
        dst[off + 1] = 0L;
        dst[off + 2] = 0L;
    }

    static boolean equals(long[] a, int aOff, long[] b, int bOff)
    {
        return a[aOff] == b[bOff]
            && a[aOff + 1] == b[bOff + 1]
            && a[aOff + 2] == b[bOff + 2];
    }

    static void add(long[] dst, int dOff, long[] a, int aOff, long[] b, int bOff)
    {
        long l0 = a[aOff]     ^ b[bOff];
        long l1 = a[aOff + 1] ^ b[bOff + 1];
        long l2 = a[aOff + 2] ^ b[bOff + 2];
        dst[dOff]     = l0;
        dst[dOff + 1] = l1;
        dst[dOff + 2] = l2;
    }

    static void addInPlace(long[] acc, int accOff, long[] x, int xOff)
    {
        acc[accOff]     ^= x[xOff];
        acc[accOff + 1] ^= x[xOff + 1];
        acc[accOff + 2] ^= x[xOff + 2];
    }

    /** {@code dst := a * x} — multiplication by the field generator. faest-ref:
     *  {@code bf192_dbl}, fields.c:455. */
    static void dbl(long[] dst, int dOff, long[] a, int aOff)
    {
        long a0 = a[aOff], a1 = a[aOff + 1], a2 = a[aOff + 2];
        long mask = -((a2 >>> 63) & 1L);
        dst[dOff]     = (a0 << 1) ^ (mask & MODULUS);
        dst[dOff + 1] = (a1 << 1) | (a0 >>> 63);
        dst[dOff + 2] = (a2 << 1) | (a1 >>> 63);
    }

    /** {@code sumPoly(xs)} per faest-ref {@code bf192_sum_poly}, fields.c:464. */
    static void sumPoly(long[] dst, int dOff, long[] xs, int xsOff)
    {
        long[] ret = new long[LIMBS];
        System.arraycopy(xs, xsOff + (192 - 1) * LIMBS, ret, 0, LIMBS);
        for (int i = 1; i < 192; i++)
        {
            dbl(ret, 0, ret, 0);
            int o = xsOff + (192 - 1 - i) * LIMBS;
            ret[0] ^= xs[o];
            ret[1] ^= xs[o + 1];
            ret[2] ^= xs[o + 2];
        }
        dst[dOff]     = ret[0];
        dst[dOff + 1] = ret[1];
        dst[dOff + 2] = ret[2];
    }

    /**
     * {@code dst := a * b} in GF(2^192). Bit-serial shift-and-reduce. faest-ref:
     * {@code bf192_mul}, fields.c:425.
     */
    static void mul(long[] dst, int dOff, long[] a, int aOff, long[] b, int bOff)
    {
        long a0 = a[aOff],     a1 = a[aOff + 1], a2 = a[aOff + 2];
        long b0 = b[bOff],     b1 = b[bOff + 1], b2 = b[bOff + 2];

        long mask = -(b0 & 1L);
        long r0 = a0 & mask, r1 = a1 & mask, r2 = a2 & mask;

        for (int idx = 1; idx != 192; ++idx)
        {
            long carry = a2 >>> 63;
            a2 = (a2 << 1) | (a1 >>> 63);
            a1 = (a1 << 1) | (a0 >>> 63);
            a0 = (a0 << 1) ^ (-carry & MODULUS);

            long bit;
            if (idx < 64)
            {
                bit = b0 >>> idx;
            }
            else if (idx < 128)
            {
                bit = b1 >>> (idx - 64);
            }
            else
            {
                bit = b2 >>> (idx - 128);
            }
            mask = -(bit & 1L);
            r0 ^= a0 & mask;
            r1 ^= a1 & mask;
            r2 ^= a2 & mask;
        }

        dst[dOff]     = r0;
        dst[dOff + 1] = r1;
        dst[dOff + 2] = r2;
    }

    /**
     * {@code dst := a * b} for {@code b} in GF(2^64). 64-iteration variant of
     * {@link #mul}. faest-ref: {@code bf192_mul_64}, fields.c:437.
     */
    static void mul64(long[] dst, int dOff, long[] a, int aOff, long b)
    {
        long a0 = a[aOff], a1 = a[aOff + 1], a2 = a[aOff + 2];
        long mask = -(b & 1L);
        long r0 = a0 & mask, r1 = a1 & mask, r2 = a2 & mask;
        for (int idx = 1; idx != 64; ++idx)
        {
            long carry = a2 >>> 63;
            a2 = (a2 << 1) | (a1 >>> 63);
            a1 = (a1 << 1) | (a0 >>> 63);
            a0 = (a0 << 1) ^ (-carry & MODULUS);
            mask = -((b >>> idx) & 1L);
            r0 ^= a0 & mask;
            r1 ^= a1 & mask;
            r2 ^= a2 & mask;
        }
        dst[dOff]     = r0;
        dst[dOff + 1] = r1;
        dst[dOff + 2] = r2;
    }

    static void load(long[] dst, int off, byte[] src, int srcOff)
    {
        dst[off]     = Pack.littleEndianToLong(src, srcOff);
        dst[off + 1] = Pack.littleEndianToLong(src, srcOff + 8);
        dst[off + 2] = Pack.littleEndianToLong(src, srcOff + 16);
    }

    static void store(byte[] dst, int dstOff, long[] src, int off)
    {
        Pack.longToLittleEndian(src[off],     dst, dstOff);
        Pack.longToLittleEndian(src[off + 1], dst, dstOff + 8);
        Pack.longToLittleEndian(src[off + 2], dst, dstOff + 16);
    }
}
