package org.bouncycastle.pqc.crypto.faest;

import org.bouncycastle.util.Pack;

/**
 * GF(2^256) arithmetic for FAEST v2.0.
 * <p>
 * Reduction polynomial: x^256 + x^10 + x^5 + x^2 + 1 (modulus low-word 0x425).
 * Elements are stored as four 64-bit limbs little-endian.
 * <p>
 * faest-ref source of truth: {@code fields.c} (bf256_*).
 */
final class BF256
{
    /** Reduction-polynomial low word. faest-ref: fields.c:21. */
    static final long MODULUS = (1L << 10) | (1L << 5) | (1L << 2) | 1L;

    static final int LIMBS = 4;
    static final int BYTES = 32;

    /** Precomputed alpha^1..alpha^7 for GF(2^8) embedded in GF(2^256). faest-ref: bf256_alpha. */
    static final long[][] ALPHA = {
        { 0x969788420bdefee7L, 0xbed68d38a0474e67L, 0xdf229845f8f1e16aL, 0x04c9a8cf20c95833L },
        { 0xa95af52ad52289c1L, 0x2ba5c48d2c42072fL, 0xd14a0d376c00b0eaL, 0x064e4d699c5b4af1L },
        { 0x55dab3833f809d1dL, 0x1771831e533b0f57L, 0xfb96573fad3fac10L, 0x6195e3db7011f68dL },
        { 0xde010519b01bcdd5L, 0x752758911a30e3f6L, 0x2a0778b6489ea03fL, 0x56c24fd64f768838L },
        { 0x98c2f529e98a30b6L, 0x1bc4dbd440f18482L, 0x2fbe09947d49a981L, 0x22270b6d71574ffcL },
        { 0x9e75afb9de44670bL, 0xaced66c666f1afbcL, 0xf001253ff2991f7eL, 0xc03d372fd1fa29f3L },
        { 0xba43b698b332e88bL, 0x5237c4d625b86f0dL, 0x2f652b2af4e81545L, 0x133eea09d26b7bb8L },
    };

    private BF256()
    {
    }

    static void getAlpha(long[] dst, int dOff, int idx)
    {
        dst[dOff]     = ALPHA[idx][0];
        dst[dOff + 1] = ALPHA[idx][1];
        dst[dOff + 2] = ALPHA[idx][2];
        dst[dOff + 3] = ALPHA[idx][3];
    }

    static void fromBit(long[] dst, int dOff, int bit)
    {
        dst[dOff]     = bit & 1L;
        dst[dOff + 1] = 0L;
        dst[dOff + 2] = 0L;
        dst[dOff + 3] = 0L;
    }

    static void mulBit(long[] dst, int dOff, long[] a, int aOff, int bit)
    {
        long mask = -((long)bit & 1L);
        dst[dOff]     = a[aOff]     & mask;
        dst[dOff + 1] = a[aOff + 1] & mask;
        dst[dOff + 2] = a[aOff + 2] & mask;
        dst[dOff + 3] = a[aOff + 3] & mask;
    }

    static void sqBit(long[] out, int outOff, long[] in, int inOff)
    {
        long i00 = in[inOff],      i01 = in[inOff + 1],  i02 = in[inOff + 2],  i03 = in[inOff + 3];
        long i10 = in[inOff + 4],  i11 = in[inOff + 5],  i12 = in[inOff + 6],  i13 = in[inOff + 7];
        long i20 = in[inOff + 8],  i21 = in[inOff + 9],  i22 = in[inOff + 10], i23 = in[inOff + 11];
        long i30 = in[inOff + 12], i31 = in[inOff + 13], i32 = in[inOff + 14], i33 = in[inOff + 15];
        long i40 = in[inOff + 16], i41 = in[inOff + 17], i42 = in[inOff + 18], i43 = in[inOff + 19];
        long i50 = in[inOff + 20], i51 = in[inOff + 21], i52 = in[inOff + 22], i53 = in[inOff + 23];
        long i60 = in[inOff + 24], i61 = in[inOff + 25], i62 = in[inOff + 26], i63 = in[inOff + 27];
        long i70 = in[inOff + 28], i71 = in[inOff + 29], i72 = in[inOff + 30], i73 = in[inOff + 31];

        // out[0] = in[0]^in[4]^in[6]
        out[outOff]     = i00 ^ i40 ^ i60;
        out[outOff + 1] = i01 ^ i41 ^ i61;
        out[outOff + 2] = i02 ^ i42 ^ i62;
        out[outOff + 3] = i03 ^ i43 ^ i63;
        // out[1] = in[4]^in[6]^in[7]
        out[outOff + 4] = i40 ^ i60 ^ i70;
        out[outOff + 5] = i41 ^ i61 ^ i71;
        out[outOff + 6] = i42 ^ i62 ^ i72;
        out[outOff + 7] = i43 ^ i63 ^ i73;
        // out[2] = in[1]^in[5]
        out[outOff + 8]  = i10 ^ i50;
        out[outOff + 9]  = i11 ^ i51;
        out[outOff + 10] = i12 ^ i52;
        out[outOff + 11] = i13 ^ i53;
        // out[3] = in[4]^in[5]^in[6]^in[7]
        out[outOff + 12] = i40 ^ i50 ^ i60 ^ i70;
        out[outOff + 13] = i41 ^ i51 ^ i61 ^ i71;
        out[outOff + 14] = i42 ^ i52 ^ i62 ^ i72;
        out[outOff + 15] = i43 ^ i53 ^ i63 ^ i73;
        // out[4] = in[2]^in[4]^in[7]
        out[outOff + 16] = i20 ^ i40 ^ i70;
        out[outOff + 17] = i21 ^ i41 ^ i71;
        out[outOff + 18] = i22 ^ i42 ^ i72;
        out[outOff + 19] = i23 ^ i43 ^ i73;
        // out[5] = in[5]^in[6]
        out[outOff + 20] = i50 ^ i60;
        out[outOff + 21] = i51 ^ i61;
        out[outOff + 22] = i52 ^ i62;
        out[outOff + 23] = i53 ^ i63;
        // out[6] = in[3]^in[5]
        out[outOff + 24] = i30 ^ i50;
        out[outOff + 25] = i31 ^ i51;
        out[outOff + 26] = i32 ^ i52;
        out[outOff + 27] = i33 ^ i53;
        // out[7] = in[6]^in[7]
        out[outOff + 28] = i60 ^ i70;
        out[outOff + 29] = i61 ^ i71;
        out[outOff + 30] = i62 ^ i72;
        out[outOff + 31] = i63 ^ i73;
    }

    static void byteCombine(long[] dst, int dOff, long[] x, int xOff)
    {
        long l0 = x[xOff], l1 = x[xOff + 1], l2 = x[xOff + 2], l3 = x[xOff + 3];
        long[] tmp = new long[LIMBS];
        for (int i = 1; i < 8; i++)
        {
            mul(tmp, 0, x, xOff + i * LIMBS, ALPHA[i - 1], 0);
            l0 ^= tmp[0]; l1 ^= tmp[1]; l2 ^= tmp[2]; l3 ^= tmp[3];
        }
        dst[dOff]     = l0;
        dst[dOff + 1] = l1;
        dst[dOff + 2] = l2;
        dst[dOff + 3] = l3;
    }

    static void byteCombineBits(long[] dst, int dOff, byte[] bits, int bitsOff)
    {
        long l0 = (bits[bitsOff] & 1L);
        long l1 = 0L, l2 = 0L, l3 = 0L;
        for (int i = 1; i < 8; i++)
        {
            long mask = -((long)(bits[bitsOff + i]) & 1L);
            l0 ^= ALPHA[i - 1][0] & mask;
            l1 ^= ALPHA[i - 1][1] & mask;
            l2 ^= ALPHA[i - 1][2] & mask;
            l3 ^= ALPHA[i - 1][3] & mask;
        }
        dst[dOff]     = l0;
        dst[dOff + 1] = l1;
        dst[dOff + 2] = l2;
        dst[dOff + 3] = l3;
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
        dst[off + 3] = 0L;
    }

    static void one(long[] dst, int off)
    {
        dst[off]     = 1L;
        dst[off + 1] = 0L;
        dst[off + 2] = 0L;
        dst[off + 3] = 0L;
    }

    static boolean equals(long[] a, int aOff, long[] b, int bOff)
    {
        return a[aOff] == b[bOff]
            && a[aOff + 1] == b[bOff + 1]
            && a[aOff + 2] == b[bOff + 2]
            && a[aOff + 3] == b[bOff + 3];
    }

    static void add(long[] dst, int dOff, long[] a, int aOff, long[] b, int bOff)
    {
        long l0 = a[aOff]     ^ b[bOff];
        long l1 = a[aOff + 1] ^ b[bOff + 1];
        long l2 = a[aOff + 2] ^ b[bOff + 2];
        long l3 = a[aOff + 3] ^ b[bOff + 3];
        dst[dOff]     = l0;
        dst[dOff + 1] = l1;
        dst[dOff + 2] = l2;
        dst[dOff + 3] = l3;
    }

    static void addInPlace(long[] acc, int accOff, long[] x, int xOff)
    {
        acc[accOff]     ^= x[xOff];
        acc[accOff + 1] ^= x[xOff + 1];
        acc[accOff + 2] ^= x[xOff + 2];
        acc[accOff + 3] ^= x[xOff + 3];
    }

    /** {@code dst := a * x} — multiplication by the field generator. faest-ref:
     *  {@code bf256_dbl}, fields.c:653. */
    static void dbl(long[] dst, int dOff, long[] a, int aOff)
    {
        long a0 = a[aOff], a1 = a[aOff + 1], a2 = a[aOff + 2], a3 = a[aOff + 3];
        long mask = -((a3 >>> 63) & 1L);
        dst[dOff]     = (a0 << 1) ^ (mask & MODULUS);
        dst[dOff + 1] = (a1 << 1) | (a0 >>> 63);
        dst[dOff + 2] = (a2 << 1) | (a1 >>> 63);
        dst[dOff + 3] = (a3 << 1) | (a2 >>> 63);
    }

    /** {@code sumPoly(xs)} per faest-ref {@code bf256_sum_poly}. */
    static void sumPoly(long[] dst, int dOff, long[] xs, int xsOff)
    {
        long[] ret = new long[LIMBS];
        System.arraycopy(xs, xsOff + (256 - 1) * LIMBS, ret, 0, LIMBS);
        for (int i = 1; i < 256; i++)
        {
            dbl(ret, 0, ret, 0);
            int o = xsOff + (256 - 1 - i) * LIMBS;
            ret[0] ^= xs[o];
            ret[1] ^= xs[o + 1];
            ret[2] ^= xs[o + 2];
            ret[3] ^= xs[o + 3];
        }
        dst[dOff]     = ret[0];
        dst[dOff + 1] = ret[1];
        dst[dOff + 2] = ret[2];
        dst[dOff + 3] = ret[3];
    }

    /**
     * {@code dst := a * b} in GF(2^256). Bit-serial shift-and-reduce. faest-ref:
     * {@code bf256_mul}, fields.c:609.
     */
    static void mul(long[] dst, int dOff, long[] a, int aOff, long[] b, int bOff)
    {
        long a0 = a[aOff],     a1 = a[aOff + 1], a2 = a[aOff + 2], a3 = a[aOff + 3];
        long b0 = b[bOff],     b1 = b[bOff + 1], b2 = b[bOff + 2], b3 = b[bOff + 3];

        long mask = -(b0 & 1L);
        long r0 = a0 & mask, r1 = a1 & mask, r2 = a2 & mask, r3 = a3 & mask;

        for (int idx = 1; idx != 256; ++idx)
        {
            long carry = a3 >>> 63;
            a3 = (a3 << 1) | (a2 >>> 63);
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
            else if (idx < 192)
            {
                bit = b2 >>> (idx - 128);
            }
            else
            {
                bit = b3 >>> (idx - 192);
            }
            mask = -(bit & 1L);
            r0 ^= a0 & mask;
            r1 ^= a1 & mask;
            r2 ^= a2 & mask;
            r3 ^= a3 & mask;
        }

        dst[dOff]     = r0;
        dst[dOff + 1] = r1;
        dst[dOff + 2] = r2;
        dst[dOff + 3] = r3;
    }

    /**
     * {@code dst := a * b} for {@code b} in GF(2^64). 64-iteration variant of
     * {@link #mul}. faest-ref: {@code bf256_mul_64}, fields.c:628.
     */
    static void mul64(long[] dst, int dOff, long[] a, int aOff, long b)
    {
        long a0 = a[aOff], a1 = a[aOff + 1], a2 = a[aOff + 2], a3 = a[aOff + 3];
        long mask = -(b & 1L);
        long r0 = a0 & mask, r1 = a1 & mask, r2 = a2 & mask, r3 = a3 & mask;
        for (int idx = 1; idx != 64; ++idx)
        {
            long carry = a3 >>> 63;
            a3 = (a3 << 1) | (a2 >>> 63);
            a2 = (a2 << 1) | (a1 >>> 63);
            a1 = (a1 << 1) | (a0 >>> 63);
            a0 = (a0 << 1) ^ (-carry & MODULUS);
            mask = -((b >>> idx) & 1L);
            r0 ^= a0 & mask;
            r1 ^= a1 & mask;
            r2 ^= a2 & mask;
            r3 ^= a3 & mask;
        }
        dst[dOff]     = r0;
        dst[dOff + 1] = r1;
        dst[dOff + 2] = r2;
        dst[dOff + 3] = r3;
    }

    static void load(long[] dst, int off, byte[] src, int srcOff)
    {
        dst[off]     = Pack.littleEndianToLong(src, srcOff);
        dst[off + 1] = Pack.littleEndianToLong(src, srcOff + 8);
        dst[off + 2] = Pack.littleEndianToLong(src, srcOff + 16);
        dst[off + 3] = Pack.littleEndianToLong(src, srcOff + 24);
    }

    static void store(byte[] dst, int dstOff, long[] src, int off)
    {
        Pack.longToLittleEndian(src[off],     dst, dstOff);
        Pack.longToLittleEndian(src[off + 1], dst, dstOff + 8);
        Pack.longToLittleEndian(src[off + 2], dst, dstOff + 16);
        Pack.longToLittleEndian(src[off + 3], dst, dstOff + 24);
    }
}
