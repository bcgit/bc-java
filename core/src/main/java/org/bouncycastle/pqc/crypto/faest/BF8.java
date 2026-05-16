package org.bouncycastle.pqc.crypto.faest;

/**
 * GF(2^8) arithmetic for FAEST v2.0's S-box computation.
 * <p>
 * Reduction polynomial: x^8 + x^4 + x^3 + x + 1 (modulus low-word 0x1b),
 * the standard AES Rijndael polynomial.
 * <p>
 * Everything here is bit-serial constant-time &mdash; no S-box / inverse table
 * lookups. This matters in FAEST because the inputs to {@link #inv} (and
 * therefore the S-box) are derived from the secret AES key; a table-based
 * implementation would leak the key via cache timing.
 * <p>
 * faest-ref source of truth: {@code fields.c} (bf8_*).
 */
final class BF8
{
    /** Reduction-polynomial low byte = AES Rijndael polynomial. faest-ref: fields.c:13. */
    static final int MODULUS = 0x1b;

    private BF8()
    {
    }

    /** {@code a * b} in GF(2^8). faest-ref: {@code bf8_mul}, fields.c:71. */
    static int mul(int a, int b)
    {
        a &= 0xff;
        b &= 0xff;
        int result = -(b & 1) & a;
        for (int idx = 1; idx < 8; ++idx)
        {
            int mask = -((a >>> 7) & 1);
            a = ((a << 1) ^ (mask & MODULUS)) & 0xff;
            result ^= -((b >>> idx) & 1) & a;
        }
        return result & 0xff;
    }

    /** {@code a^2} in GF(2^8). faest-ref: {@code bf8_square}, fields.c:81. */
    static int square(int a)
    {
        return mul(a, a);
    }

    /**
     * {@code a^-1} in GF(2^8) via repeated squaring: {@code a^254}.
     * {@code bf8_inv(0) == 0} by the squaring chain, which is the convention
     * the AES S-box relies on. faest-ref: {@code bf8_inv}, fields.c:92.
     */
    static int inv(int a)
    {
        int t2   = square(a);
        int t3   = mul(a, t2);
        int t5   = mul(t3, t2);
        int t7   = mul(t5, t2);
        int t14  = square(t7);
        int t28  = square(t14);
        int t56  = square(t28);
        int t63  = mul(t56, t7);
        int t126 = square(t63);
        int t252 = square(t126);
        return mul(t252, t2);
    }

    /**
     * Squaring on the GF(2^8) "bit-vector" representation: {@code x} is an
     * eight-element array where {@code x[i]} holds bit {@code i} of the
     * GF(2^8) element. Outputs {@code x[i]^2}'s bit representation in place.
     * Used by the FAEST proof primitives to square bit-decomposed witnesses
     * without going through {@link #square}. faest-ref: {@code bits_sq},
     * fields.c:44.
     */
    static void bits_sq(byte[] x)
    {
        byte x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
        byte x4 = x[4], x5 = x[5], x6 = x[6], x7 = x[7];
        x[0] = (byte)(x0 ^ x4 ^ x6);
        x[1] = (byte)(x4 ^ x6 ^ x7);
        x[2] = (byte)(x1 ^ x5);
        x[3] = (byte)(x4 ^ x5 ^ x6 ^ x7);
        x[4] = (byte)(x2 ^ x4 ^ x7);
        x[5] = (byte)(x5 ^ x6);
        x[6] = (byte)(x3 ^ x5);
        x[7] = (byte)(x6 ^ x7);
    }

    /** XOR-parity of the eight bits of {@code v}. */
    static int parity(int v)
    {
        v &= 0xff;
        v ^= v >>> 4;
        v ^= v >>> 2;
        v ^= v >>> 1;
        return v & 1;
    }
}
