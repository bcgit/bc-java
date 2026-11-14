package org.bouncycastle.math.raw;

/**
 * Constant-time GF(2^8) primitives over the AES reduction polynomial
 * x^8 + x^4 + x^3 + x + 1 (0x11b), with elements in the polynomial basis as
 * integers 0..255.
 * <p>
 * Every operation is safe on secret values, and callers depend on that (e.g.
 * HQC's Reed-Solomon code runs on secret-derived syndromes and error locators).
 * Nothing here may index a table by a field element, branch on one, or exit
 * early: lookup tables leak through cache-line selection, as AES T-tables do.
 * <p>
 * Only the low 8 bits of each argument are used; results are in 0..255.
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

        // Carryless multiply: each bit of a selects, by mask, a shifted copy of b,
        // so a zero operand needs no special case. The partial products for the
        // high nibble of a (d, bits 4 to 14) and for the low nibble (c, bits 0 to
        // 10) are accumulated separately.
        int d = (b << 4) & -(a & 0x10)
              ^ (b << 5) & -(a & 0x20)
              ^ (b << 6) & -(a & 0x40)
              ^ (b << 7) & -(a & 0x80);
        int c = (b << 0) & -(a & 0x01)
              ^ (b << 1) & -(a & 0x02)
              ^ (b << 2) & -(a & 0x04)
              ^ (b << 3) & -(a & 0x08);

        // Reduce with x^8 = x^4 + x^3 + x + 1 (0x1b); multiplying by
        // 0x1b = (x + 1)(x^3 + 1) is u ^= u << 1 then u ^= u << 3. First fold d's
        // bits above x^7 into c, landing at or below x^10...
        int u = d >>> 8;
        u ^= u << 1;
        u ^= u << 3;
        c ^= u;

        // ...then set c's bits above x^7 aside, add in the low byte of d (its bits
        // 4 to 7), and fold them.
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
        // Spread the low nibble to the even bit positions.
        int c = Interleave.expand4to8(a);

        // The high nibble's squares x^8, x^10, x^12 and x^14 are added already
        // reduced (0x1b, 0x6c, 0xab and 0x9a). The constants sit 8 bits up so that
        // each mask -(a & 0x10) .. -(a & 0x80), all ones from its bit upward,
        // covers them without first shifting the bit down.
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
        // Addition chain 2, 4, 8, 6, 14, 28, 56, 112, 126, 252, 254.
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
        return mul(a252, a2);        // a^254 = a^-1
    }

    /**
     * Word-parallel constant-time GF(256) scalar-times-vector multiply: returns
     * {@code s * v} where {@code v} packs eight GF(256) elements, one per byte
     * lane, and the result packs the eight products in the same lanes.
     * <p>
     * Algorithm: {@code s*v = XOR_k v_k (s . x^k)} over the 8 bits {@code v_k}
     * of each lane. The reduced multiples {@code s . x^k} are scalars, computed
     * once per call; bit {@code k} of every lane is isolated as a 0/1 byte and
     * multiplied by {@code s . x^k}, which places that multiple in each lane
     * whose bit is set (0 or 1 times a value below 256 cannot carry into the
     * next lane). The eight selections are independent of one another, where
     * doubling {@code v} k times was a serial chain, and for a scalar fixed
     * across a loop the multiples are loop-invariant. No table and no
     * data-dependent branch, so it is safe to feed secret scalars and vectors.
     */
    public static long mulFx8(int s, long v)
    {
        final long L = 0x0101010101010101L;

        int s0 = s & 0xff;
        int s1 = xtime(s0), s2 = xtime(s1), s3 = xtime(s2), s4 = xtime(s3);
        int s5 = xtime(s4), s6 = xtime(s5), s7 = xtime(s6);

        return (v         & L) * s0
            ^ ((v >>>  1) & L) * s1
            ^ ((v >>>  2) & L) * s2
            ^ ((v >>>  3) & L) * s3
            ^ ((v >>>  4) & L) * s4
            ^ ((v >>>  5) & L) * s5
            ^ ((v >>>  6) & L) * s6
            ^ ((v >>>  7) & L) * s7;
    }

    /**
     * {@code a . x} for {@code a} in 0..255: shift, and add the polynomial back
     * in (by mask, not branch) when bit 7 shifts out.
     */
    private static int xtime(int a)
    {
        return (a << 1) ^ (-(a >>> 7) & 0x11b);
    }
}
