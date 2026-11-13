package org.bouncycastle.pqc.crypto.hqc;

import org.bouncycastle.math.raw.GF256AES;

/**
 * Arithmetic in GF(2^8) = GF(2)[X]/(X^8 + X^4 + X^3 + X + 1), the field underlying HQC's
 * Reed-Solomon code (HQC specification of 2026-10-12, Section 2.1; the 2025-08-22 specification
 * used X^8 + X^4 + X^3 + X^2 + 1, so the Reed-Solomon generator polynomials and the alpha power
 * tables in {@link ReedSolomon} changed with it). This is the AES field, so the arithmetic is
 * {@link GF256AES}'s.
 * <p>
 * NOTE: these routines run on secret-derived values on both sides of the KEM -
 * {@link ReedSolomon#encode} multiplies by coefficients derived from the secret message during
 * encapsulation, and {@link ReedSolomon#decode} plus {@link FastFourierTransform} operate on
 * syndromes, error locator coefficients and root sets derived from the secret error vector during
 * decapsulation. An earlier version of this class used log/exp/inv/sqr lookup tables indexed by
 * those values, so which cache line was touched revealed the secret. {@link GF256AES} guarantees
 * table-free, branch-free operations; anything added here must only compose them.
 */
class GF
{
    static int div(int a, int b)
    {
        return GF256AES.mul(a, GF256AES.inv(b));
    }

    static int inv(int a)
    {
        return GF256AES.inv(a);
    }

    static int mul(int a, int b)
    {
        return GF256AES.mul(a, b);
    }

    static int sqr(int a)
    {
        return GF256AES.sqr(a);
    }
}
