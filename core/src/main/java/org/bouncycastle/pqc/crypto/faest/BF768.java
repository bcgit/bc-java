package org.bouncycastle.pqc.crypto.faest;

import org.bouncycastle.util.Pack;

/**
 * GF(2^768) arithmetic for FAEST v2.0 universal-hashing accumulators.
 * <p>
 * Reduction polynomial: x^768 + x^19 + x^17 + x^4 + 1 (modulus low-word 0xA0011).
 * Elements are stored as twelve 64-bit limbs little-endian.
 * <p>
 * Asymmetric multiplication: BF768 &times; BF256 &rarr; BF768. Mirrors
 * {@code bf768_mul_256} in {@code faest-ref/fields.c:891}.
 * <p>
 * faest-ref source of truth: {@code fields.c} (bf768_*).
 */
final class BF768
{
    /** Reduction-polynomial low word. faest-ref: fields.c:27. */
    static final long MODULUS = (1L << 19) | (1L << 17) | (1L << 4) | 1L;

    static final int LIMBS = 12;
    static final int BYTES = 96;

    private BF768()
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
     * {@code dst := a * b} where {@code a} lives in GF(2^768) and {@code b}
     * lives in GF(2^256). Bit-serial over the 256 bits of {@code b}; the lhs
     * is shifted left by one bit per iteration with reduction against the
     * BF768 modulus. faest-ref: {@code bf768_mul_256}, fields.c:891.
     */
    static void mul256(long[] dst, int dOff,
                       long[] a, int aOff,
                       long[] b, int bOff)
    {
        long a0  = a[aOff],     a1  = a[aOff + 1],  a2  = a[aOff + 2];
        long a3  = a[aOff + 3], a4  = a[aOff + 4],  a5  = a[aOff + 5];
        long a6  = a[aOff + 6], a7  = a[aOff + 7],  a8  = a[aOff + 8];
        long a9  = a[aOff + 9], a10 = a[aOff + 10], a11 = a[aOff + 11];
        long b0  = b[bOff],     b1  = b[bOff + 1],  b2  = b[bOff + 2], b3 = b[bOff + 3];

        long mask = -(b0 & 1L);
        long r0  = a0  & mask, r1  = a1  & mask, r2  = a2  & mask;
        long r3  = a3  & mask, r4  = a4  & mask, r5  = a5  & mask;
        long r6  = a6  & mask, r7  = a7  & mask, r8  = a8  & mask;
        long r9  = a9  & mask, r10 = a10 & mask, r11 = a11 & mask;

        for (int idx = 1; idx != 256; ++idx)
        {
            long carry = a11 >>> 63;
            a11 = (a11 << 1) | (a10 >>> 63);
            a10 = (a10 << 1) | (a9  >>> 63);
            a9  = (a9  << 1) | (a8  >>> 63);
            a8  = (a8  << 1) | (a7  >>> 63);
            a7  = (a7  << 1) | (a6  >>> 63);
            a6  = (a6  << 1) | (a5  >>> 63);
            a5  = (a5  << 1) | (a4  >>> 63);
            a4  = (a4  << 1) | (a3  >>> 63);
            a3  = (a3  << 1) | (a2  >>> 63);
            a2  = (a2  << 1) | (a1  >>> 63);
            a1  = (a1  << 1) | (a0  >>> 63);
            a0  = (a0  << 1) ^ (-carry & MODULUS);

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
            r0  ^= a0  & mask;
            r1  ^= a1  & mask;
            r2  ^= a2  & mask;
            r3  ^= a3  & mask;
            r4  ^= a4  & mask;
            r5  ^= a5  & mask;
            r6  ^= a6  & mask;
            r7  ^= a7  & mask;
            r8  ^= a8  & mask;
            r9  ^= a9  & mask;
            r10 ^= a10 & mask;
            r11 ^= a11 & mask;
        }

        dst[dOff]      = r0;
        dst[dOff + 1]  = r1;
        dst[dOff + 2]  = r2;
        dst[dOff + 3]  = r3;
        dst[dOff + 4]  = r4;
        dst[dOff + 5]  = r5;
        dst[dOff + 6]  = r6;
        dst[dOff + 7]  = r7;
        dst[dOff + 8]  = r8;
        dst[dOff + 9]  = r9;
        dst[dOff + 10] = r10;
        dst[dOff + 11] = r11;
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
