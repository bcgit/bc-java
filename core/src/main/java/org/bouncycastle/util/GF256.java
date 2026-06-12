package org.bouncycastle.util;

/**
 * Constant-time GF(2^8) primitives over the AES reduction polynomial
 * x^8 + x^4 + x^3 + x + 1 (0x11b).
 * <p>
 * Shared home for the word-parallel bitsliced scalar-times-vector multiply used
 * by the multivariate / MPC-in-the-head schemes (SDitH, UOV, ...). Companion to
 * {@link GF16} for the GF(2^4) nibble field.
 */
public class GF256
{
    private GF256()
    {
    }

    /**
     * Word-parallel constant-time GF(256) scalar-times-vector multiply: returns
     * {@code s * v} where {@code v} packs eight GF(256) elements, one per byte
     * lane, and the result packs the eight products in the same lanes.
     * <p>
     * Algorithm: {@code s*v = XOR_k s_k (x^k . v)} over the 8 bits {@code s_k}
     * of the scalar, where {@code x^k . v} is {@code k}-fold GF(256) doubling
     * (xtime) of every lane. xtime is the branchless SWAR step
     * {@code ((v<<1) & 0xFE..) ^ ((v>>>7 & 0x01..) * 0x1b)}, and each scalar bit
     * selects via the mask {@code -(s_k)} (0 or -1). No table and no
     * data-dependent branch, so it is safe to feed secret scalars (the operand
     * of a secret-share multiply-accumulate).
     */
    public static long mulFx8(int s, long v)
    {
        s &= 0xff;
        long acc = v & -((long)(s & 1));
        for (int k = 1; k < 8; ++k)
        {
            long hi = (v >>> 7) & 0x0101010101010101L;
            v = ((v << 1) & 0xfefefefefefefefeL) ^ (hi * 0x1bL);
            acc ^= v & -((long)((s >>> k) & 1));
        }
        return acc;
    }
}
