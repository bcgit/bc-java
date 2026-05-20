package org.bouncycastle.pqc.crypto.faest;

import java.security.SecureRandom;

import org.bouncycastle.util.test.SimpleTest;

/**
 * Algebraic-invariant tests for FAEST's three binary-extension fields.
 * <p>
 * Three layers of coverage:
 * <ol>
 *   <li>Fixed-element tests: identities ({@code a+0=a}, {@code a*1=a},
 *       {@code a+a=0}, {@code a*0=0}) and a small set of known small values.</li>
 *   <li>Reduction sanity: multiply the top-bit-only element by the spec's
 *       {@code alpha = x} (i.e. left-shift) and verify the low limb folds to
 *       the reduction-polynomial low word.</li>
 *   <li>Randomised algebraic invariants over 100 iterations seeded with a
 *       fixed-byte stream so the test is deterministic.</li>
 * </ol>
 * <p>
 * Byte-level KAT vectors against the reference implementation are exercised
 * indirectly through the end-to-end sign/verify KATs (FaestTest), which only
 * pass if every field operation is correct.
 */
public class FaestFieldTest
    extends SimpleTest
{
    private static final int ITERATIONS = 100;

    public String getName()
    {
        return "FaestField";
    }

    public void performTest()
        throws Exception
    {
        bf128_identities();
        bf128_reduction();
        bf128_random_invariants();

        bf192_identities();
        bf192_reduction();
        bf192_random_invariants();

        bf256_identities();
        bf256_reduction();
        bf256_random_invariants();
    }

    // ----- BF128 -----

    private void bf128_identities()
    {
        long[] zero = new long[2]; BF128.zero(zero, 0);
        long[] one  = new long[2]; BF128.one(one, 0);
        long[] a    = new long[]{0x0123456789abcdefL, 0xfedcba9876543210L};

        long[] tmp = new long[2];
        BF128.add(tmp, 0, a, 0, zero, 0);
        isTrue("BF128 a+0=a", BF128.equals(tmp, 0, a, 0));

        BF128.add(tmp, 0, a, 0, a, 0);
        isTrue("BF128 a+a=0", BF128.equals(tmp, 0, zero, 0));

        BF128.mul(tmp, 0, a, 0, one, 0);
        isTrue("BF128 a*1=a", BF128.equals(tmp, 0, a, 0));

        BF128.mul(tmp, 0, one, 0, a, 0);
        isTrue("BF128 1*a=a", BF128.equals(tmp, 0, a, 0));

        BF128.mul(tmp, 0, a, 0, zero, 0);
        isTrue("BF128 a*0=0", BF128.equals(tmp, 0, zero, 0));

        BF128.mul(tmp, 0, one, 0, one, 0);
        isTrue("BF128 1*1=1", BF128.equals(tmp, 0, one, 0));
    }

    private void bf128_reduction()
    {
        // alpha = x (bit 1 set)
        long[] alpha = new long[]{2L, 0L};
        // top-bit-only element: bit 127 set
        long[] top = new long[]{0L, 1L << 63};
        // top * alpha = x^128 (overflow) which reduces to MODULUS
        long[] result = new long[2];
        BF128.mul(result, 0, top, 0, alpha, 0);
        long[] expected = new long[]{BF128.MODULUS, 0L};
        isTrue("BF128 x^127 * x reduces to MODULUS", BF128.equals(result, 0, expected, 0));
    }

    private void bf128_random_invariants()
    {
        SecureRandom rng = fixedSeed("BF128");
        long[] a = new long[2], b = new long[2], c = new long[2];
        long[] t1 = new long[2], t2 = new long[2], t3 = new long[2], t4 = new long[2];
        byte[] buf = new byte[BF128.BYTES];

        for (int i = 0; i < ITERATIONS; i++)
        {
            randomElement(rng, buf, a, BF128.BYTES, BF128.LIMBS);
            randomElement(rng, buf, b, BF128.BYTES, BF128.LIMBS);
            randomElement(rng, buf, c, BF128.BYTES, BF128.LIMBS);

            // commutativity: a*b == b*a
            BF128.mul(t1, 0, a, 0, b, 0);
            BF128.mul(t2, 0, b, 0, a, 0);
            isTrue("BF128 a*b == b*a", BF128.equals(t1, 0, t2, 0));

            // distributivity: a*(b+c) == a*b + a*c
            BF128.add(t1, 0, b, 0, c, 0);
            BF128.mul(t2, 0, a, 0, t1, 0);
            BF128.mul(t3, 0, a, 0, b, 0);
            BF128.mul(t4, 0, a, 0, c, 0);
            BF128.add(t3, 0, t3, 0, t4, 0);
            isTrue("BF128 a*(b+c) == a*b + a*c", BF128.equals(t2, 0, t3, 0));

            // associativity (add): (a+b)+c == a+(b+c)
            BF128.add(t1, 0, a, 0, b, 0);
            BF128.add(t1, 0, t1, 0, c, 0);
            BF128.add(t2, 0, b, 0, c, 0);
            BF128.add(t2, 0, a, 0, t2, 0);
            isTrue("BF128 (a+b)+c == a+(b+c)", BF128.equals(t1, 0, t2, 0));

            // associativity (mul): (a*b)*c == a*(b*c)
            BF128.mul(t1, 0, a, 0, b, 0);
            BF128.mul(t1, 0, t1, 0, c, 0);
            BF128.mul(t2, 0, b, 0, c, 0);
            BF128.mul(t2, 0, a, 0, t2, 0);
            isTrue("BF128 (a*b)*c == a*(b*c)", BF128.equals(t1, 0, t2, 0));

            // load(store(a)) == a
            BF128.store(buf, 0, a, 0);
            BF128.load(t1, 0, buf, 0);
            isTrue("BF128 load(store(a)) == a", BF128.equals(t1, 0, a, 0));
        }
    }

    // ----- BF192 -----

    private void bf192_identities()
    {
        long[] zero = new long[3]; BF192.zero(zero, 0);
        long[] one  = new long[3]; BF192.one(one, 0);
        long[] a    = new long[]{0x0123456789abcdefL, 0xfedcba9876543210L, 0x1122334455667788L};

        long[] tmp = new long[3];
        BF192.add(tmp, 0, a, 0, zero, 0);
        isTrue("BF192 a+0=a", BF192.equals(tmp, 0, a, 0));

        BF192.add(tmp, 0, a, 0, a, 0);
        isTrue("BF192 a+a=0", BF192.equals(tmp, 0, zero, 0));

        BF192.mul(tmp, 0, a, 0, one, 0);
        isTrue("BF192 a*1=a", BF192.equals(tmp, 0, a, 0));

        BF192.mul(tmp, 0, a, 0, zero, 0);
        isTrue("BF192 a*0=0", BF192.equals(tmp, 0, zero, 0));

        BF192.mul(tmp, 0, one, 0, one, 0);
        isTrue("BF192 1*1=1", BF192.equals(tmp, 0, one, 0));
    }

    private void bf192_reduction()
    {
        long[] alpha = new long[]{2L, 0L, 0L};
        long[] top   = new long[]{0L, 0L, 1L << 63};
        long[] result = new long[3];
        BF192.mul(result, 0, top, 0, alpha, 0);
        long[] expected = new long[]{BF192.MODULUS, 0L, 0L};
        isTrue("BF192 x^191 * x reduces to MODULUS", BF192.equals(result, 0, expected, 0));
    }

    private void bf192_random_invariants()
    {
        SecureRandom rng = fixedSeed("BF192");
        long[] a = new long[3], b = new long[3], c = new long[3];
        long[] t1 = new long[3], t2 = new long[3], t3 = new long[3], t4 = new long[3];
        byte[] buf = new byte[BF192.BYTES];

        for (int i = 0; i < ITERATIONS; i++)
        {
            randomElement(rng, buf, a, BF192.BYTES, BF192.LIMBS);
            randomElement(rng, buf, b, BF192.BYTES, BF192.LIMBS);
            randomElement(rng, buf, c, BF192.BYTES, BF192.LIMBS);

            BF192.mul(t1, 0, a, 0, b, 0);
            BF192.mul(t2, 0, b, 0, a, 0);
            isTrue("BF192 a*b == b*a", BF192.equals(t1, 0, t2, 0));

            BF192.add(t1, 0, b, 0, c, 0);
            BF192.mul(t2, 0, a, 0, t1, 0);
            BF192.mul(t3, 0, a, 0, b, 0);
            BF192.mul(t4, 0, a, 0, c, 0);
            BF192.add(t3, 0, t3, 0, t4, 0);
            isTrue("BF192 distributivity", BF192.equals(t2, 0, t3, 0));

            BF192.mul(t1, 0, a, 0, b, 0);
            BF192.mul(t1, 0, t1, 0, c, 0);
            BF192.mul(t2, 0, b, 0, c, 0);
            BF192.mul(t2, 0, a, 0, t2, 0);
            isTrue("BF192 associativity (mul)", BF192.equals(t1, 0, t2, 0));

            BF192.store(buf, 0, a, 0);
            BF192.load(t1, 0, buf, 0);
            isTrue("BF192 load(store(a)) == a", BF192.equals(t1, 0, a, 0));
        }
    }

    // ----- BF256 -----

    private void bf256_identities()
    {
        long[] zero = new long[4]; BF256.zero(zero, 0);
        long[] one  = new long[4]; BF256.one(one, 0);
        long[] a    = new long[]{0x0123456789abcdefL, 0xfedcba9876543210L,
                                  0x1122334455667788L, 0x99aabbccddeeff00L};

        long[] tmp = new long[4];
        BF256.add(tmp, 0, a, 0, zero, 0);
        isTrue("BF256 a+0=a", BF256.equals(tmp, 0, a, 0));

        BF256.add(tmp, 0, a, 0, a, 0);
        isTrue("BF256 a+a=0", BF256.equals(tmp, 0, zero, 0));

        BF256.mul(tmp, 0, a, 0, one, 0);
        isTrue("BF256 a*1=a", BF256.equals(tmp, 0, a, 0));

        BF256.mul(tmp, 0, a, 0, zero, 0);
        isTrue("BF256 a*0=0", BF256.equals(tmp, 0, zero, 0));

        BF256.mul(tmp, 0, one, 0, one, 0);
        isTrue("BF256 1*1=1", BF256.equals(tmp, 0, one, 0));
    }

    private void bf256_reduction()
    {
        long[] alpha = new long[]{2L, 0L, 0L, 0L};
        long[] top   = new long[]{0L, 0L, 0L, 1L << 63};
        long[] result = new long[4];
        BF256.mul(result, 0, top, 0, alpha, 0);
        long[] expected = new long[]{BF256.MODULUS, 0L, 0L, 0L};
        isTrue("BF256 x^255 * x reduces to MODULUS", BF256.equals(result, 0, expected, 0));
    }

    private void bf256_random_invariants()
    {
        SecureRandom rng = fixedSeed("BF256");
        long[] a = new long[4], b = new long[4], c = new long[4];
        long[] t1 = new long[4], t2 = new long[4], t3 = new long[4], t4 = new long[4];
        byte[] buf = new byte[BF256.BYTES];

        for (int i = 0; i < ITERATIONS; i++)
        {
            randomElement(rng, buf, a, BF256.BYTES, BF256.LIMBS);
            randomElement(rng, buf, b, BF256.BYTES, BF256.LIMBS);
            randomElement(rng, buf, c, BF256.BYTES, BF256.LIMBS);

            BF256.mul(t1, 0, a, 0, b, 0);
            BF256.mul(t2, 0, b, 0, a, 0);
            isTrue("BF256 a*b == b*a", BF256.equals(t1, 0, t2, 0));

            BF256.add(t1, 0, b, 0, c, 0);
            BF256.mul(t2, 0, a, 0, t1, 0);
            BF256.mul(t3, 0, a, 0, b, 0);
            BF256.mul(t4, 0, a, 0, c, 0);
            BF256.add(t3, 0, t3, 0, t4, 0);
            isTrue("BF256 distributivity", BF256.equals(t2, 0, t3, 0));

            BF256.mul(t1, 0, a, 0, b, 0);
            BF256.mul(t1, 0, t1, 0, c, 0);
            BF256.mul(t2, 0, b, 0, c, 0);
            BF256.mul(t2, 0, a, 0, t2, 0);
            isTrue("BF256 associativity (mul)", BF256.equals(t1, 0, t2, 0));

            BF256.store(buf, 0, a, 0);
            BF256.load(t1, 0, buf, 0);
            isTrue("BF256 load(store(a)) == a", BF256.equals(t1, 0, a, 0));
        }
    }

    // ----- helpers -----

    /**
     * Deterministic, unbounded byte stream seeded from {@code label}. We don't use
     * FixedSecureRandom here because the field invariant tests consume many KB of
     * randomness across all three sub-fields and pre-sizing a fixed buffer is
     * brittle. xorshift64 keeps the implementation tiny and reproducible.
     */
    private static SecureRandom fixedSeed(final String label)
    {
        return new SecureRandom()
        {
            private long state = seedFromLabel(label);

            @Override
            public void nextBytes(byte[] bytes)
            {
                for (int i = 0; i < bytes.length; i++)
                {
                    state ^= state << 13;
                    state ^= state >>> 7;
                    state ^= state << 17;
                    bytes[i] = (byte)state;
                }
            }
        };
    }

    private static long seedFromLabel(String label)
    {
        long h = 0xcbf29ce484222325L;       // FNV-1a 64-bit offset basis
        for (int i = 0; i < label.length(); i++)
        {
            h ^= label.charAt(i);
            h *= 0x100000001b3L;
        }
        // xorshift64 deadlocks on zero; this constant can't be zero given the
        // FNV-1a offset starter, but guard anyway.
        return h == 0L ? 1L : h;
    }

    private static void randomElement(SecureRandom rng, byte[] buf, long[] dst, int bytes, int limbs)
    {
        rng.nextBytes(buf);
        // load via the appropriate field's helper would require a per-field switch;
        // here we just do it inline since the buf size matches the limb count.
        for (int i = 0; i < limbs; i++)
        {
            long v = 0;
            for (int j = 0; j < 8; j++)
            {
                v |= ((long)(buf[i * 8 + j] & 0xff)) << (j * 8);
            }
            dst[i] = v;
        }
    }

    public static void main(String[] args)
    {
        runTest(new FaestFieldTest());
    }
}
