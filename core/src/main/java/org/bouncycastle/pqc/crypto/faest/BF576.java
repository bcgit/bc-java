package org.bouncycastle.pqc.crypto.faest;

import org.bouncycastle.util.Pack;

/**
 * GF(2^576) arithmetic for FAEST v2.0 universal-hashing accumulators.
 * <p>
 * Reduction polynomial: x^576 + x^13 + x^4 + x^3 + 1 (modulus low-word 0x2019).
 * Elements are stored as nine 64-bit limbs little-endian.
 * <p>
 * Asymmetric multiplication: BF576 &times; BF192 &rarr; BF576. Mirrors
 * {@code bf576_mul_192} in {@code faest-ref/fields.c:806}.
 * <p>
 * faest-ref source of truth: {@code fields.c} (bf576_*).
 */
final class BF576
{
    /** Reduction-polynomial low word. faest-ref: fields.c:25. */
    static final long MODULUS = (1L << 13) | (1L << 4) | (1L << 3) | 1L;

    static final int LIMBS = 9;
    static final int BYTES = 72;

    private BF576()
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
     * {@code dst := a * b} where {@code a} lives in GF(2^576) and {@code b}
     * lives in GF(2^192). Bit-serial over the 192 bits of {@code b}; the lhs
     * is shifted left by one bit per iteration with reduction against the
     * BF576 modulus. faest-ref: {@code bf576_mul_192}, fields.c:806.
     */
    static void mul192(long[] dst, int dOff,
                       long[] a, int aOff,
                       long[] b, int bOff)
    {
        long a0 = a[aOff],     a1 = a[aOff + 1], a2 = a[aOff + 2];
        long a3 = a[aOff + 3], a4 = a[aOff + 4], a5 = a[aOff + 5];
        long a6 = a[aOff + 6], a7 = a[aOff + 7], a8 = a[aOff + 8];
        long b0 = b[bOff],     b1 = b[bOff + 1], b2 = b[bOff + 2];

        long mask = -(b0 & 1L);
        long r0 = a0 & mask, r1 = a1 & mask, r2 = a2 & mask;
        long r3 = a3 & mask, r4 = a4 & mask, r5 = a5 & mask;
        long r6 = a6 & mask, r7 = a7 & mask, r8 = a8 & mask;

        for (int idx = 1; idx != 192; ++idx)
        {
            long carry = a8 >>> 63;
            a8 = (a8 << 1) | (a7 >>> 63);
            a7 = (a7 << 1) | (a6 >>> 63);
            a6 = (a6 << 1) | (a5 >>> 63);
            a5 = (a5 << 1) | (a4 >>> 63);
            a4 = (a4 << 1) | (a3 >>> 63);
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
            else
            {
                bit = b2 >>> (idx - 128);
            }
            mask = -(bit & 1L);
            r0 ^= a0 & mask;
            r1 ^= a1 & mask;
            r2 ^= a2 & mask;
            r3 ^= a3 & mask;
            r4 ^= a4 & mask;
            r5 ^= a5 & mask;
            r6 ^= a6 & mask;
            r7 ^= a7 & mask;
            r8 ^= a8 & mask;
        }

        dst[dOff]     = r0;
        dst[dOff + 1] = r1;
        dst[dOff + 2] = r2;
        dst[dOff + 3] = r3;
        dst[dOff + 4] = r4;
        dst[dOff + 5] = r5;
        dst[dOff + 6] = r6;
        dst[dOff + 7] = r7;
        dst[dOff + 8] = r8;
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
