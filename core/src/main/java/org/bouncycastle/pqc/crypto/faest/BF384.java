package org.bouncycastle.pqc.crypto.faest;

import org.bouncycastle.util.Pack;

/**
 * GF(2^384) arithmetic for FAEST v2.0 universal-hashing accumulators.
 * <p>
 * Reduction polynomial: x^384 + x^12 + x^3 + x^2 + 1 (modulus low-word 0x100D).
 * Elements are stored as six 64-bit limbs little-endian.
 * <p>
 * The only multiplication exposed is <em>asymmetric</em>: a BF384 element times
 * a BF128 element, returning a BF384 element. This mirrors {@code bf384_mul_128}
 * in {@code faest-ref/fields.c:727} &mdash; universal hashing never multiplies
 * two BF384 elements together.
 * <p>
 * faest-ref source of truth: {@code fields.c} (bf384_*).
 */
final class BF384
{
    /** Reduction-polynomial low word. faest-ref: fields.c:23. */
    static final long MODULUS = (1L << 12) | (1L << 3) | (1L << 2) | 1L;

    static final int LIMBS = 6;
    static final int BYTES = 48;

    private BF384()
    {
    }

    static void zero(long[] dst, int off)
    {
        for (int i = 0; i < LIMBS; i++)
        {
            dst[off + i] = 0L;
        }
    }

    static void one(long[] dst, int off)
    {
        dst[off] = 1L;
        for (int i = 1; i < LIMBS; i++)
        {
            dst[off + i] = 0L;
        }
    }

    static boolean equals(long[] a, int aOff, long[] b, int bOff)
    {
        for (int i = 0; i < LIMBS; i++)
        {
            if (a[aOff + i] != b[bOff + i])
            {
                return false;
            }
        }
        return true;
    }

    static void add(long[] dst, int dOff, long[] a, int aOff, long[] b, int bOff)
    {
        for (int i = 0; i < LIMBS; i++)
        {
            dst[dOff + i] = a[aOff + i] ^ b[bOff + i];
        }
    }

    static void addInPlace(long[] acc, int accOff, long[] x, int xOff)
    {
        for (int i = 0; i < LIMBS; i++)
        {
            acc[accOff + i] ^= x[xOff + i];
        }
    }

    /**
     * {@code dst := a * b} where {@code a} lives in GF(2^384) and {@code b}
     * lives in GF(2^128). The multiplication is bit-serial over the 128 bits
     * of {@code b}; at each step {@code a} is shifted left by one with
     * reduction against the BF384 modulus. faest-ref: {@code bf384_mul_128},
     * fields.c:727.
     */
    static void mul128(long[] dst, int dOff,
                       long[] a, int aOff,
                       long[] b, int bOff)
    {
        long a0 = a[aOff],     a1 = a[aOff + 1], a2 = a[aOff + 2];
        long a3 = a[aOff + 3], a4 = a[aOff + 4], a5 = a[aOff + 5];
        long b0 = b[bOff],     b1 = b[bOff + 1];

        long mask = -(b0 & 1L);
        long r0 = a0 & mask, r1 = a1 & mask, r2 = a2 & mask;
        long r3 = a3 & mask, r4 = a4 & mask, r5 = a5 & mask;

        for (int idx = 1; idx != 128; ++idx)
        {
            long carry = a5 >>> 63;
            a5 = (a5 << 1) | (a4 >>> 63);
            a4 = (a4 << 1) | (a3 >>> 63);
            a3 = (a3 << 1) | (a2 >>> 63);
            a2 = (a2 << 1) | (a1 >>> 63);
            a1 = (a1 << 1) | (a0 >>> 63);
            a0 = (a0 << 1) ^ (-carry & MODULUS);

            long bit = idx < 64 ? (b0 >>> idx) : (b1 >>> (idx - 64));
            mask = -(bit & 1L);
            r0 ^= a0 & mask;
            r1 ^= a1 & mask;
            r2 ^= a2 & mask;
            r3 ^= a3 & mask;
            r4 ^= a4 & mask;
            r5 ^= a5 & mask;
        }

        dst[dOff]     = r0;
        dst[dOff + 1] = r1;
        dst[dOff + 2] = r2;
        dst[dOff + 3] = r3;
        dst[dOff + 4] = r4;
        dst[dOff + 5] = r5;
    }

    static void load(long[] dst, int off, byte[] src, int srcOff)
    {
        for (int i = 0; i < LIMBS; i++)
        {
            dst[off + i] = Pack.littleEndianToLong(src, srcOff + i * 8);
        }
    }

    static void store(byte[] dst, int dstOff, long[] src, int off)
    {
        for (int i = 0; i < LIMBS; i++)
        {
            Pack.longToLittleEndian(src[off + i], dst, dstOff + i * 8);
        }
    }
}
