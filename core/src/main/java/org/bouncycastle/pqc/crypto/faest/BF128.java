package org.bouncycastle.pqc.crypto.faest;

import org.bouncycastle.util.Pack;

/**
 * GF(2^128) arithmetic for FAEST v2.0.
 * <p>
 * Reduction polynomial: x^128 + x^7 + x^2 + x + 1 (modulus low-word 0x87).
 * <p>
 * Elements are stored as a pair of unsigned 64-bit limbs in <em>little-endian</em>
 * order: {@code limbs[off]} is the low 64 bits, {@code limbs[off + 1]} is the
 * high 64 bits. All operations take output / input arrays + offsets so callers
 * can pack many elements into a single {@code long[]} without per-element
 * allocation &mdash; matching how {@code faest-ref/fields.c} packs the
 * {@code bf128_t} arrays used by the VOLE-AES inner loops.
 * <p>
 * faest-ref source of truth: {@code fields.c} (bf128_*).
 */
final class BF128
{
    /** Reduction-polynomial low word. faest-ref: fields.c:17. */
    static final long MODULUS = (1L << 7) | (1L << 2) | (1L << 1) | 1L;

    /** Number of 64-bit limbs per element. */
    static final int LIMBS = 2;
    /** Byte width of a packed element. */
    static final int BYTES = 16;

    /**
     * Precomputed {@code alpha^i} for {@code i} in 1..7, where alpha is the
     * generator of the GF(2^8) subfield embedded in GF(2^128). Used by the
     * byte-combine helpers. Values copied verbatim from faest-ref fields.c
     * {@code bf128_alpha}.
     */
    static final long[][] ALPHA = {
        { 0xa13fe8ac5560ce0dL, 0x053d8555a9979a1cL },
        { 0xec7759ca3488aee1L, 0x4cf4b7439cbfbb84L },
        { 0xbfcf02ae363946a8L, 0x35ad604f7d51d2c6L },
        { 0x6b8330483c2e9849L, 0x0dcb364640a222feL },
        { 0x252b49277b1b82b4L, 0x549810e11a88dea5L },
        { 0xc72bf2ef2521ff22L, 0xd681a5686c0c1f75L },
        { 0x7a7a8e94e136f9bcL, 0x0950311a4fb78fe0L },
    };

    private BF128()
    {
    }

    /** Write {@code ALPHA[idx]} into {@code dst[dOff..dOff+LIMBS]}. faest-ref: {@code bf128_get_alpha}. */
    static void getAlpha(long[] dst, int dOff, int idx)
    {
        dst[dOff]     = ALPHA[idx][0];
        dst[dOff + 1] = ALPHA[idx][1];
    }

    /** {@code dst := bit & 1}. faest-ref: {@code bf128_from_bit}. */
    static void fromBit(long[] dst, int dOff, int bit)
    {
        dst[dOff]     = bit & 1L;
        dst[dOff + 1] = 0L;
    }

    /** {@code dst := a & -(bit & 1)}. faest-ref: {@code bf128_mul_bit}. */
    static void mulBit(long[] dst, int dOff, long[] a, int aOff, int bit)
    {
        long mask = -((long)bit & 1L);
        dst[dOff]     = a[aOff]     & mask;
        dst[dOff + 1] = a[aOff + 1] & mask;
    }

    /**
     * Bit-vector squaring: 8 GF(2^128) elements squared simultaneously via
     * the GF(2^8) bit-recurrence. Same coefficient pattern as
     * {@link BF8#bits_sq}. faest-ref: {@code bf128_sq_bit}, fields.c:157.
     */
    static void sqBit(long[] out, int outOff, long[] in, int inOff)
    {
        // Capture the eight input elements first; in/out may alias.
        long i0lo = in[inOff],     i0hi = in[inOff + 1];
        long i1lo = in[inOff + 2], i1hi = in[inOff + 3];
        long i2lo = in[inOff + 4], i2hi = in[inOff + 5];
        long i3lo = in[inOff + 6], i3hi = in[inOff + 7];
        long i4lo = in[inOff + 8], i4hi = in[inOff + 9];
        long i5lo = in[inOff + 10], i5hi = in[inOff + 11];
        long i6lo = in[inOff + 12], i6hi = in[inOff + 13];
        long i7lo = in[inOff + 14], i7hi = in[inOff + 15];

        out[outOff]      = i0lo ^ i4lo ^ i6lo;
        out[outOff + 1]  = i0hi ^ i4hi ^ i6hi;
        out[outOff + 2]  = i4lo ^ i6lo ^ i7lo;
        out[outOff + 3]  = i4hi ^ i6hi ^ i7hi;
        out[outOff + 4]  = i1lo ^ i5lo;
        out[outOff + 5]  = i1hi ^ i5hi;
        out[outOff + 6]  = i4lo ^ i5lo ^ i6lo ^ i7lo;
        out[outOff + 7]  = i4hi ^ i5hi ^ i6hi ^ i7hi;
        out[outOff + 8]  = i2lo ^ i4lo ^ i7lo;
        out[outOff + 9]  = i2hi ^ i4hi ^ i7hi;
        out[outOff + 10] = i5lo ^ i6lo;
        out[outOff + 11] = i5hi ^ i6hi;
        out[outOff + 12] = i3lo ^ i5lo;
        out[outOff + 13] = i3hi ^ i5hi;
        out[outOff + 14] = i6lo ^ i7lo;
        out[outOff + 15] = i6hi ^ i7hi;
    }

    /**
     * {@code dst := x[0] + sum_{i=1..7} x[i] * alpha^i}. Folds 8 GF(2^128)
     * elements into one via the alpha basis. faest-ref: {@code bf128_byte_combine},
     * fields.c:149.
     */
    static void byteCombine(long[] dst, int dOff, long[] x, int xOff)
    {
        long lo = x[xOff];
        long hi = x[xOff + 1];
        long[] tmp = new long[LIMBS];
        for (int i = 1; i < 8; i++)
        {
            mul(tmp, 0, x, xOff + i * LIMBS, ALPHA[i - 1], 0);
            lo ^= tmp[0];
            hi ^= tmp[1];
        }
        dst[dOff]     = lo;
        dst[dOff + 1] = hi;
    }

    /**
     * {@code dst := from_bit(bits[0]) + sum_{i=1..7} mul_bit(alpha^i, bits[i])}.
     * {@code bits[i]} is a byte holding a single bit in the lsb. faest-ref:
     * {@code bf128_byte_combine_bits}, fields.c:174.
     */
    static void byteCombineBits(long[] dst, int dOff, byte[] bits, int bitsOff)
    {
        long lo = (bits[bitsOff] & 1L);
        long hi = 0L;
        for (int i = 1; i < 8; i++)
        {
            long mask = -((long)(bits[bitsOff + i]) & 1L);
            lo ^= ALPHA[i - 1][0] & mask;
            hi ^= ALPHA[i - 1][1] & mask;
        }
        dst[dOff]     = lo;
        dst[dOff + 1] = hi;
    }

    /** Convenience: {@link #sqBit} followed by {@link #byteCombine}. */
    static void byteCombineSq(long[] dst, int dOff, long[] x, int xOff)
    {
        long[] sq = new long[8 * LIMBS];
        sqBit(sq, 0, x, xOff);
        byteCombine(dst, dOff, sq, 0);
    }

    /** Convenience: {@link BF8#bits_sq} followed by {@link #byteCombineBits}. */
    static void byteCombineBitsSq(long[] dst, int dOff, byte[] bits, int bitsOff)
    {
        byte[] y = new byte[8];
        System.arraycopy(bits, bitsOff, y, 0, 8);
        BF8.bits_sq(y);
        byteCombineBits(dst, dOff, y, 0);
    }

    /** Write the additive identity into {@code dst[off..off+LIMBS]}. */
    static void zero(long[] dst, int off)
    {
        dst[off] = 0L;
        dst[off + 1] = 0L;
    }

    /** Write the multiplicative identity into {@code dst[off..off+LIMBS]}. */
    static void one(long[] dst, int off)
    {
        dst[off] = 1L;
        dst[off + 1] = 0L;
    }

    /** {@code a == b} on limb tuples. */
    static boolean equals(long[] a, int aOff, long[] b, int bOff)
    {
        return a[aOff] == b[bOff] && a[aOff + 1] == b[bOff + 1];
    }

    /** {@code dst := a + b} (XOR). Safe with overlap. faest-ref: bf128_add macro. */
    static void add(long[] dst, int dOff, long[] a, int aOff, long[] b, int bOff)
    {
        long lo = a[aOff] ^ b[bOff];
        long hi = a[aOff + 1] ^ b[bOff + 1];
        dst[dOff] = lo;
        dst[dOff + 1] = hi;
    }

    /** {@code acc ^= x}. */
    static void addInPlace(long[] acc, int accOff, long[] x, int xOff)
    {
        acc[accOff]     ^= x[xOff];
        acc[accOff + 1] ^= x[xOff + 1];
    }

    /** {@code dst := a * x} — multiplication by the field generator. faest-ref:
     *  {@code bf128_dbl}, fields.c:276. */
    static void dbl(long[] dst, int dOff, long[] a, int aOff)
    {
        long aLo = a[aOff], aHi = a[aOff + 1];
        long mask = -((aHi >>> 63) & 1L);
        dst[dOff]     = (aLo << 1) ^ (mask & MODULUS);
        dst[dOff + 1] = (aHi << 1) | (aLo >>> 63);
    }

    /** {@code dst := sum_{i=0..127} xs[127-i] * alpha^i} — Horner evaluation at
     *  alpha (= the field generator x). faest-ref: {@code bf128_sum_poly},
     *  fields.c:284. */
    static void sumPoly(long[] dst, int dOff, long[] xs, int xsOff)
    {
        long[] ret = new long[LIMBS];
        System.arraycopy(xs, xsOff + (128 - 1) * LIMBS, ret, 0, LIMBS);
        for (int i = 1; i < 128; i++)
        {
            dbl(ret, 0, ret, 0);
            ret[0] ^= xs[xsOff + (128 - 1 - i) * LIMBS];
            ret[1] ^= xs[xsOff + (128 - 1 - i) * LIMBS + 1];
        }
        dst[dOff]     = ret[0];
        dst[dOff + 1] = ret[1];
    }

    /**
     * {@code dst := a * b} in GF(2^128). Bit-serial shift-and-reduce: at each
     * step shift {@code a} left by one bit, fold the high-bit overflow into
     * {@code a[0]} via {@code MODULUS}, and XOR {@code a} into the result when
     * the corresponding bit of {@code b} is set. faest-ref: {@code bf128_mul},
     * fields.c:246.
     */
    static void mul(long[] dst, int dOff, long[] a, int aOff, long[] b, int bOff)
    {
        long aLo = a[aOff],     aHi = a[aOff + 1];
        long bLo = b[bOff],     bHi = b[bOff + 1];

        // bit 0 of b
        long mask = -(bLo & 1L);
        long rLo = aLo & mask;
        long rHi = aHi & mask;

        for (int idx = 1; idx != 128; ++idx)
        {
            // shift a left by one, with reduction
            long carry = aHi >>> 63;
            aHi = (aHi << 1) | (aLo >>> 63);
            aLo = (aLo << 1) ^ (-carry & MODULUS);

            // bit idx of b
            long bit = idx < 64 ? (bLo >>> idx) : (bHi >>> (idx - 64));
            mask = -(bit & 1L);
            rLo ^= aLo & mask;
            rHi ^= aHi & mask;
        }

        dst[dOff] = rLo;
        dst[dOff + 1] = rHi;
    }

    /**
     * {@code dst := a * b} where {@code b} is a 64-bit field element from GF(2^64)
     * embedded into BF128. Same bit-serial reduction as {@link #mul} but only 64
     * iterations. faest-ref: {@code bf128_mul_64}, fields.c:258.
     */
    static void mul64(long[] dst, int dOff, long[] a, int aOff, long b)
    {
        long aLo = a[aOff], aHi = a[aOff + 1];
        long mask = -(b & 1L);
        long rLo = aLo & mask;
        long rHi = aHi & mask;
        for (int idx = 1; idx != 64; ++idx)
        {
            long carry = aHi >>> 63;
            aHi = (aHi << 1) | (aLo >>> 63);
            aLo = (aLo << 1) ^ (-carry & MODULUS);
            mask = -((b >>> idx) & 1L);
            rLo ^= aLo & mask;
            rHi ^= aHi & mask;
        }
        dst[dOff] = rLo;
        dst[dOff + 1] = rHi;
    }

    /**
     * Load element from {@code src[srcOff..srcOff+BYTES]} (little-endian) into
     * {@code dst[off..off+LIMBS]}.
     */
    static void load(long[] dst, int off, byte[] src, int srcOff)
    {
        dst[off]     = Pack.littleEndianToLong(src, srcOff);
        dst[off + 1] = Pack.littleEndianToLong(src, srcOff + 8);
    }

    /**
     * Store element from {@code src[off..off+LIMBS]} into {@code dst[dstOff..dstOff+BYTES]}
     * little-endian.
     */
    static void store(byte[] dst, int dstOff, long[] src, int off)
    {
        Pack.longToLittleEndian(src[off],     dst, dstOff);
        Pack.longToLittleEndian(src[off + 1], dst, dstOff + 8);
    }
}
