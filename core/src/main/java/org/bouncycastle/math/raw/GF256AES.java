package org.bouncycastle.math.raw;

/**
 * Constant-time GF(2^8) primitives over the AES reduction polynomial
 * x^8 + x^4 + x^3 + x + 1 (0x11b).
 * <p>
 * The {@code AES} suffix names that specific irreducible polynomial: GF(2^8) is a
 * single field up to isomorphism but admits many representations, and the AES
 * choice is by far the most common (also used by SM4, GHASH's sibling fields,
 * etc.). The polynomial alone pins down the arithmetic — e.g. Rainbow's GF(2^8)
 * uses a tower basis whose products differ, so it deliberately does not share
 * this class. Callers relying on the AES element encoding should depend on the
 * name, not just "GF(256)".
 * <p>
 * Shared home for the word-parallel bitsliced scalar-times-vector multiply used
 * by the multivariate / MPC-in-the-head schemes (SDitH, UOV, ...). Companion to
 * {@link GF16} for the GF(2^4) nibble field.
 */
public class GF256AES
{
    private GF256AES()
    {
    }

    /**
     * Constant-time GF(256) scalar multiply over the AES polynomial 0x11b:
     * returns {@code a * b}. The Russian-peasant loop doubles one operand
     * (branchless xtime {@code (b<<1) ^ (carry * 0x1b)}) and conditionally adds
     * it under the mask {@code -(bit)} (0 or -1) for each bit of the other, so
     * there is no table lookup and no data-dependent branch — safe to feed
     * secret operands. This is the scalar companion of {@link #mulFx8(int, long)}
     * and is byte-identical to the per-scheme forms it replaces (UOV's mul256,
     * SDitH's mulNaive, MQOM's gf256Mult).
     */
    public static int mul(int a, int b)
    {
        a &= 0xff;
        b &= 0xff;
        int acc = b & -(a & 1);
        for (int k = 1; k < 8; ++k)
        {
            int hi = (b >>> 7) & 1;
            b = ((b << 1) & 0xfe) ^ (hi * 0x1b);
            acc ^= b & -((a >>> k) & 1);
        }
        return acc & 0xff;
    }

    /**
     * Constant-time GF(256) squaring over 0x11b. Squaring is GF(2)-linear, so
     * {@code a^2} is just the bit-spread of {@code a} (interleave a zero between
     * each bit, via {@link Interleave#expand8to16(int)}) reduced mod 0x11b. The
     * reduction folds the high byte back twice: {@code x^8 = x^4 + x^3 + x + 1}
     * means a high coefficient block multiplies by 0x1b, computed branchlessly as
     * {@code (d ^= d<<1; d ^= d<<3)} = {@code d * (1+x)(1+x^3) = d * 0x1b}. Returns
     * the same value as {@link #mul(int, int) mul(a, a)} but with no
     * data-dependent loop — table-free, branchless, and measurably faster
     * (~2.6x on HotSpot C2), so it replaces the squarings in {@link #inv(int)}.
     */
    public static int sqr(int a)
    {
        // a^2 unreduced: bits 0..14, even positions only.
        int c = Interleave.expand8to16(a);
        // reduce x^8..x^15 -> x^0..x^11  (fold the high byte * 0x1b)
        int d = c >>> 8; c &= 0xff;
        d ^= d << 1;
        d ^= d << 3;
        c ^= d;
        // reduce the residual x^8..x^11 -> x^0..x^7
        int e = c >>> 8; c &= 0xff;
        e ^= e << 1;
        e ^= e << 3;
        c ^= e;
        return c;
    }

    /**
     * Constant-time GF(256) multiplicative inverse over 0x11b via the Fermat
     * addition chain {@code a^254 = a^-1} (since {@code a^255 = 1} for nonzero
     * {@code a}). The chain maps {@code 0 -> 0}, so no data-dependent zero check
     * is needed and none is done: branching on zero-ness would leak whether a
     * (secret-derived) value was singular. No table is used. The seven squarings
     * go through the dedicated {@link #sqr(int)}; the four genuine products
     * through {@link #mul(int, int)}.
     */
    public static int inv(int a)
    {
        a &= 0xff;
        int a2 = sqr(a);             // a^2
        int a4 = sqr(a2);            // a^4
        int a8 = sqr(a4);            // a^8
        int a6 = mul(a4, a2);        // a^6
        int a14 = mul(a8, a6);       // a^14
        int a112 = sqr(a14);         // a^28
        a112 = sqr(a112);            // a^56
        a112 = sqr(a112);            // a^112
        int a126 = mul(a112, a14);   // a^126
        int a252 = sqr(a126);        // a^252
        return mul(a252, a2);        // a^254 = a^-1
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
