package org.bouncycastle.pqc.crypto.hqc;

/**
 * Arithmetic in GF(2^8) = GF(2)[X]/(X^8 + X^4 + X^3 + X^2 + 1), the field underlying HQC's
 * Reed-Solomon code.
 * <p>
 * NOTE: every operation here is table-free and branch-free on purpose. These routines run on
 * secret-derived values on both sides of the KEM - {@link ReedSolomon#encode} multiplies by
 * coefficients derived from the secret message during encapsulation, and
 * {@link ReedSolomon#decode} plus {@link FastFourierTransform} operate on syndromes, error
 * locator coefficients and root sets derived from the secret error vector during decapsulation.
 * An earlier version of this class used the classic log/exp/inv/sqr lookup tables (256 int
 * entries, i.e. 16 cache lines each) indexed by those values, so which cache line was touched
 * revealed the secret: the same secret-dependent-memory-access weakness as an AES T-table
 * implementation. Do not reintroduce a table indexed by a field element, and do not replace the
 * fixed-count loops below with early exits or data-dependent branches - the constant iteration
 * count is the point, not an oversight.
 */
class GF
{
    /**
     * The field polynomial X^8 + X^4 + X^3 + X^2 + 1, including its X^8 term, as a bit pattern.
     */
    private static final int MODULUS = 0x11D;

    /**
     * Reduce a carryless product of two field elements (degree at most 14) modulo
     * {@link #MODULUS}. Clearing bit i can only set bits below i, so a single descending pass
     * suffices; the conditional XOR is applied as a mask so no branch depends on the value.
     */
    private static int reduce(int x)
    {
        for (int i = 14; i >= 8; --i)
        {
            int m = -((x >>> i) & 1);
            x ^= m & (MODULUS << (i - 8));
        }

        return x & 0xFF;
    }

    static int mul(int a, int b)
    {
        // carryless multiply: XOR the shifted copies of a selected by the set bits of b. A zero
        // operand needs no special case, it simply selects nothing and leaves the product zero.
        int p = 0;
        for (int i = 0; i < 8; ++i)
        {
            int m = -((b >>> i) & 1);
            p ^= m & (a << i);
        }

        return reduce(p);
    }

    static int mul3(int a, int b, int c)
    {
        return mul(mul(a, b), c);
    }

    static int sqr(int a)
    {
        // squaring is linear over GF(2): spreading the bits of a to the even positions of a
        // 15-bit value yields a(X)^2 directly, there are no cross terms to accumulate.
        int x = a;
        x = (x | (x << 4)) & 0x0F0F;
        x = (x | (x << 2)) & 0x3333;
        x = (x | (x << 1)) & 0x5555;

        return reduce(x);
    }

    static int inv(int a)
    {
        // a^254 = a^-1 for a != 0, since a^255 = 1; and 0^254 = 0, matching the inverse of zero
        // being defined as zero here. Addition chain 2, 3, 6, 7, 14, 15, 30, 31, 62, 63, 126,
        // 127, 254: seven squarings and six multiplications, all of them constant-time.
        int a2 = sqr(a);
        int a3 = mul(a2, a);
        int a6 = sqr(a3);
        int a7 = mul(a6, a);
        int a14 = sqr(a7);
        int a15 = mul(a14, a);
        int a30 = sqr(a15);
        int a31 = mul(a30, a);
        int a62 = sqr(a31);
        int a63 = mul(a62, a);
        int a126 = sqr(a63);
        int a127 = mul(a126, a);

        return sqr(a127);
    }

    static int div(int a, int b)
    {
        return mul(a, inv(b));
    }
}
