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
     * returns {@code a * b}. There is no table lookup and no data-dependent branch
     *  — safe to feed secret operands. This is the scalar companion of
     * {@link #mulFx8(int, long)} and is byte-identical to the per-scheme forms it
     *  replaces (UOV's mul256, SDitH's mulNaive, MQOM's gf256Mult).
     */
    public static int mul(int a, int b)
    {
        b &= 0xff;

        int d = (b << 4) & -(a & 0x10)
              ^ (b << 5) & -(a & 0x20)
              ^ (b << 6) & -(a & 0x40)
              ^ (b << 7) & -(a & 0x80);
        int c = (b << 0) & -(a & 0x01)
              ^ (b << 1) & -(a & 0x02)
              ^ (b << 2) & -(a & 0x04)
              ^ (b << 3) & -(a & 0x08);

        // reduce x^8..x^15 -> x^0..x^11
        int u = d >>> 8;
        u ^= u << 1;
        u ^= u << 3;
        c ^= u;

        // reduce x^8..x^11 -> x^0..x^7
        int v = c >>> 8; c = (c ^ d) & 0xff;
        v ^= v << 1;
        v ^= v << 3;
        c ^= v;

        return c;        
    }

    /**
     * Constant-time GF(256) squaring over 0x11b. Squaring is GF(2)-linear, so
     * {@code a^2} is just the bit-spread of {@code a} (interleave a zero between
     * each bit), reduced mod 0x11b.
     */
    public static int sqr(int a)
    {
        int c = Interleave.expand4to8(a);
        int hi = 0x1b00 & -(a & 0x10)
               ^ 0x6c00 & -(a & 0x20)
               ^ 0xab00 & -(a & 0x40)
               ^ 0x9a00 & -(a & 0x80);
        return c ^ (hi >>> 8);        
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
        int a28 = sqr(a14);          // a^28
        int a56 = sqr(a28);          // a^56
        int a112 = sqr(a56);         // a^112
        int a126 = mul(a112, a14);   // a^126
        int a252 = sqr(a126);        // a^252
        int a254 = mul(a252, a2);    // a^254 = a^-1
        return a254;
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
