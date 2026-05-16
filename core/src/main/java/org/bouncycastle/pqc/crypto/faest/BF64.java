package org.bouncycastle.pqc.crypto.faest;

import org.bouncycastle.util.Pack;

/**
 * GF(2^64) arithmetic for FAEST v2.0 universal hashing.
 * <p>
 * Reduction polynomial: x^64 + x^4 + x^3 + x + 1 (modulus low-word 0x1b).
 * Elements are bare {@code long} values (little-endian when serialized).
 * <p>
 * faest-ref source of truth: {@code fields.c} (bf64_*).
 */
final class BF64
{
    /** Reduction-polynomial low word. faest-ref: fields.c:15. */
    static final long MODULUS = (1L << 4) | (1L << 3) | (1L << 1) | 1L;

    static final int BYTES = 8;

    private BF64()
    {
    }

    /** {@code a * b} in GF(2^64). faest-ref: {@code bf64_mul}, fields.c:114. */
    static long mul(long a, long b)
    {
        long result = -(b & 1L) & a;
        for (int idx = 1; idx != 64; ++idx)
        {
            long mask = -((a >>> 63) & 1L);
            a = (a << 1) ^ (mask & MODULUS);
            result ^= -((b >>> idx) & 1L) & a;
        }
        return result;
    }

    /** Load 8 little-endian bytes into a long. */
    static long load(byte[] src, int srcOff)
    {
        return Pack.littleEndianToLong(src, srcOff);
    }

    /** Store a long as 8 little-endian bytes. */
    static void store(byte[] dst, int dstOff, long src)
    {
        Pack.longToLittleEndian(src, dst, dstOff);
    }
}
