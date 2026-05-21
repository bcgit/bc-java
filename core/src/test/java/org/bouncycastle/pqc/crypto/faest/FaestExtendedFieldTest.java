package org.bouncycastle.pqc.crypto.faest;

import java.security.SecureRandom;

import org.bouncycastle.util.test.SimpleTest;

/**
 * Algebraic-invariant tests for the asymmetric multiplications used in FAEST's
 * universal-hashing accumulators: BF384 &times; BF128, BF576 &times; BF192,
 * BF768 &times; BF256.
 * <p>
 * Each test covers:
 * <ol>
 *   <li>Identity: {@code mul(a, 0) = 0}, {@code mul(a, 1) = a}, {@code mul(0, b) = 0}.</li>
 *   <li>Right-distributivity over the smaller ring:
 *       {@code mul(a, x+y) = mul(a, x) + mul(a, y)}.</li>
 *   <li>Left-distributivity over the bigger ring:
 *       {@code mul(a+b, x) = mul(a, x) + mul(b, x)}.</li>
 *   <li>Reduction sanity: top-bit-only bigger times {@code alpha = x} should
 *       fold to the bigger-field MODULUS in the low limb.</li>
 *   <li>Load/store round-trip.</li>
 * </ol>
 * <p>
 * Byte-exact reference comparison comes from the end-to-end FaestTest KAT
 * runner; here we only verify the algebraic structure of the asymmetric
 * multiplications.
 */
public class FaestExtendedFieldTest
    extends SimpleTest
{
    private static final int ITERATIONS = 50;

    public String getName()
    {
        return "FaestExtendedField";
    }

    public void performTest()
        throws Exception
    {
        bf384_identities();
        bf384_reduction();
        bf384_distributivity();
        bf384_load_store();

        bf576_identities();
        bf576_reduction();
        bf576_distributivity();
        bf576_load_store();

        bf768_identities();
        bf768_reduction();
        bf768_distributivity();
        bf768_load_store();
    }

    // ----- BF384 (mul with BF128) -----

    private void bf384_identities()
    {
        long[] zero384 = new long[BF384.LIMBS]; BF384.zero(zero384, 0);
        long[] one384  = new long[BF384.LIMBS]; BF384.one(one384, 0);
        long[] a       = randomBigger(BF384.LIMBS, 0xa11d1cL);

        long[] zero128 = new long[BF128.LIMBS]; BF128.zero(zero128, 0);
        long[] one128  = new long[BF128.LIMBS]; BF128.one(one128, 0);

        long[] tmp = new long[BF384.LIMBS];

        BF384.mul128(tmp, 0, a, 0, zero128, 0);
        isTrue("BF384 a*0 == 0", BF384.equals(tmp, 0, zero384, 0));

        BF384.mul128(tmp, 0, a, 0, one128, 0);
        isTrue("BF384 a*1 == a", BF384.equals(tmp, 0, a, 0));

        BF384.mul128(tmp, 0, zero384, 0, one128, 0);
        isTrue("BF384 0*1 == 0", BF384.equals(tmp, 0, zero384, 0));
    }

    private void bf384_reduction()
    {
        long[] alpha = new long[]{2L, 0L};
        long[] top = new long[BF384.LIMBS];
        top[BF384.LIMBS - 1] = 1L << 63;
        long[] result = new long[BF384.LIMBS];
        BF384.mul128(result, 0, top, 0, alpha, 0);

        long[] expected = new long[BF384.LIMBS];
        expected[0] = BF384.MODULUS;
        isTrue("BF384 x^383 * x reduces to MODULUS", BF384.equals(result, 0, expected, 0));
    }

    private void bf384_distributivity()
    {
        SecureRandom rng = fixedSeed("BF384-dist");
        long[] a = new long[BF384.LIMBS], b = new long[BF384.LIMBS];
        long[] x = new long[BF128.LIMBS], y = new long[BF128.LIMBS];
        long[] sum128 = new long[BF128.LIMBS], sum384 = new long[BF384.LIMBS];
        long[] t1 = new long[BF384.LIMBS], t2 = new long[BF384.LIMBS], t3 = new long[BF384.LIMBS];

        for (int i = 0; i < ITERATIONS; i++)
        {
            randomLimbs(rng, a, BF384.LIMBS);
            randomLimbs(rng, b, BF384.LIMBS);
            randomLimbs(rng, x, BF128.LIMBS);
            randomLimbs(rng, y, BF128.LIMBS);

            // right-distributivity: a*(x+y) == a*x + a*y
            BF128.add(sum128, 0, x, 0, y, 0);
            BF384.mul128(t1, 0, a, 0, sum128, 0);
            BF384.mul128(t2, 0, a, 0, x, 0);
            BF384.mul128(t3, 0, a, 0, y, 0);
            BF384.add(t2, 0, t2, 0, t3, 0);
            isTrue("BF384 a*(x+y) == a*x + a*y", BF384.equals(t1, 0, t2, 0));

            // left-distributivity: (a+b)*x == a*x + b*x
            BF384.add(sum384, 0, a, 0, b, 0);
            BF384.mul128(t1, 0, sum384, 0, x, 0);
            BF384.mul128(t2, 0, a, 0, x, 0);
            BF384.mul128(t3, 0, b, 0, x, 0);
            BF384.add(t2, 0, t2, 0, t3, 0);
            isTrue("BF384 (a+b)*x == a*x + b*x", BF384.equals(t1, 0, t2, 0));
        }
    }

    private void bf384_load_store()
    {
        SecureRandom rng = fixedSeed("BF384-ls");
        byte[] buf = new byte[BF384.BYTES];
        long[] a = new long[BF384.LIMBS];
        long[] b = new long[BF384.LIMBS];

        for (int i = 0; i < 16; i++)
        {
            randomLimbs(rng, a, BF384.LIMBS);
            BF384.store(buf, 0, a, 0);
            BF384.load(b, 0, buf, 0);
            isTrue("BF384 load(store(a)) == a", BF384.equals(a, 0, b, 0));
        }
    }

    // ----- BF576 (mul with BF192) -----

    private void bf576_identities()
    {
        long[] zero576 = new long[BF576.LIMBS]; BF576.zero(zero576, 0);
        long[] a       = randomBigger(BF576.LIMBS, 0xb22d2cL);

        long[] zero192 = new long[BF192.LIMBS]; BF192.zero(zero192, 0);
        long[] one192  = new long[BF192.LIMBS]; BF192.one(one192, 0);

        long[] tmp = new long[BF576.LIMBS];

        BF576.mul192(tmp, 0, a, 0, zero192, 0);
        isTrue("BF576 a*0 == 0", BF576.equals(tmp, 0, zero576, 0));

        BF576.mul192(tmp, 0, a, 0, one192, 0);
        isTrue("BF576 a*1 == a", BF576.equals(tmp, 0, a, 0));

        BF576.mul192(tmp, 0, zero576, 0, one192, 0);
        isTrue("BF576 0*1 == 0", BF576.equals(tmp, 0, zero576, 0));
    }

    private void bf576_reduction()
    {
        long[] alpha = new long[]{2L, 0L, 0L};
        long[] top = new long[BF576.LIMBS];
        top[BF576.LIMBS - 1] = 1L << 63;
        long[] result = new long[BF576.LIMBS];
        BF576.mul192(result, 0, top, 0, alpha, 0);

        long[] expected = new long[BF576.LIMBS];
        expected[0] = BF576.MODULUS;
        isTrue("BF576 x^575 * x reduces to MODULUS", BF576.equals(result, 0, expected, 0));
    }

    private void bf576_distributivity()
    {
        SecureRandom rng = fixedSeed("BF576-dist");
        long[] a = new long[BF576.LIMBS], b = new long[BF576.LIMBS];
        long[] x = new long[BF192.LIMBS], y = new long[BF192.LIMBS];
        long[] sum192 = new long[BF192.LIMBS], sum576 = new long[BF576.LIMBS];
        long[] t1 = new long[BF576.LIMBS], t2 = new long[BF576.LIMBS], t3 = new long[BF576.LIMBS];

        for (int i = 0; i < ITERATIONS; i++)
        {
            randomLimbs(rng, a, BF576.LIMBS);
            randomLimbs(rng, b, BF576.LIMBS);
            randomLimbs(rng, x, BF192.LIMBS);
            randomLimbs(rng, y, BF192.LIMBS);

            BF192.add(sum192, 0, x, 0, y, 0);
            BF576.mul192(t1, 0, a, 0, sum192, 0);
            BF576.mul192(t2, 0, a, 0, x, 0);
            BF576.mul192(t3, 0, a, 0, y, 0);
            BF576.add(t2, 0, t2, 0, t3, 0);
            isTrue("BF576 a*(x+y) == a*x + a*y", BF576.equals(t1, 0, t2, 0));

            BF576.add(sum576, 0, a, 0, b, 0);
            BF576.mul192(t1, 0, sum576, 0, x, 0);
            BF576.mul192(t2, 0, a, 0, x, 0);
            BF576.mul192(t3, 0, b, 0, x, 0);
            BF576.add(t2, 0, t2, 0, t3, 0);
            isTrue("BF576 (a+b)*x == a*x + b*x", BF576.equals(t1, 0, t2, 0));
        }
    }

    private void bf576_load_store()
    {
        SecureRandom rng = fixedSeed("BF576-ls");
        byte[] buf = new byte[BF576.BYTES];
        long[] a = new long[BF576.LIMBS];
        long[] b = new long[BF576.LIMBS];

        for (int i = 0; i < 16; i++)
        {
            randomLimbs(rng, a, BF576.LIMBS);
            BF576.store(buf, 0, a, 0);
            BF576.load(b, 0, buf, 0);
            isTrue("BF576 load(store(a)) == a", BF576.equals(a, 0, b, 0));
        }
    }

    // ----- BF768 (mul with BF256) -----

    private void bf768_identities()
    {
        long[] zero768 = new long[BF768.LIMBS]; BF768.zero(zero768, 0);
        long[] a       = randomBigger(BF768.LIMBS, 0xc33d3cL);

        long[] zero256 = new long[BF256.LIMBS]; BF256.zero(zero256, 0);
        long[] one256  = new long[BF256.LIMBS]; BF256.one(one256, 0);

        long[] tmp = new long[BF768.LIMBS];

        BF768.mul256(tmp, 0, a, 0, zero256, 0);
        isTrue("BF768 a*0 == 0", BF768.equals(tmp, 0, zero768, 0));

        BF768.mul256(tmp, 0, a, 0, one256, 0);
        isTrue("BF768 a*1 == a", BF768.equals(tmp, 0, a, 0));

        BF768.mul256(tmp, 0, zero768, 0, one256, 0);
        isTrue("BF768 0*1 == 0", BF768.equals(tmp, 0, zero768, 0));
    }

    private void bf768_reduction()
    {
        long[] alpha = new long[]{2L, 0L, 0L, 0L};
        long[] top = new long[BF768.LIMBS];
        top[BF768.LIMBS - 1] = 1L << 63;
        long[] result = new long[BF768.LIMBS];
        BF768.mul256(result, 0, top, 0, alpha, 0);

        long[] expected = new long[BF768.LIMBS];
        expected[0] = BF768.MODULUS;
        isTrue("BF768 x^767 * x reduces to MODULUS", BF768.equals(result, 0, expected, 0));
    }

    private void bf768_distributivity()
    {
        SecureRandom rng = fixedSeed("BF768-dist");
        long[] a = new long[BF768.LIMBS], b = new long[BF768.LIMBS];
        long[] x = new long[BF256.LIMBS], y = new long[BF256.LIMBS];
        long[] sum256 = new long[BF256.LIMBS], sum768 = new long[BF768.LIMBS];
        long[] t1 = new long[BF768.LIMBS], t2 = new long[BF768.LIMBS], t3 = new long[BF768.LIMBS];

        for (int i = 0; i < ITERATIONS; i++)
        {
            randomLimbs(rng, a, BF768.LIMBS);
            randomLimbs(rng, b, BF768.LIMBS);
            randomLimbs(rng, x, BF256.LIMBS);
            randomLimbs(rng, y, BF256.LIMBS);

            BF256.add(sum256, 0, x, 0, y, 0);
            BF768.mul256(t1, 0, a, 0, sum256, 0);
            BF768.mul256(t2, 0, a, 0, x, 0);
            BF768.mul256(t3, 0, a, 0, y, 0);
            BF768.add(t2, 0, t2, 0, t3, 0);
            isTrue("BF768 a*(x+y) == a*x + a*y", BF768.equals(t1, 0, t2, 0));

            BF768.add(sum768, 0, a, 0, b, 0);
            BF768.mul256(t1, 0, sum768, 0, x, 0);
            BF768.mul256(t2, 0, a, 0, x, 0);
            BF768.mul256(t3, 0, b, 0, x, 0);
            BF768.add(t2, 0, t2, 0, t3, 0);
            isTrue("BF768 (a+b)*x == a*x + b*x", BF768.equals(t1, 0, t2, 0));
        }
    }

    private void bf768_load_store()
    {
        SecureRandom rng = fixedSeed("BF768-ls");
        byte[] buf = new byte[BF768.BYTES];
        long[] a = new long[BF768.LIMBS];
        long[] b = new long[BF768.LIMBS];

        for (int i = 0; i < 16; i++)
        {
            randomLimbs(rng, a, BF768.LIMBS);
            BF768.store(buf, 0, a, 0);
            BF768.load(b, 0, buf, 0);
            isTrue("BF768 load(store(a)) == a", BF768.equals(a, 0, b, 0));
        }
    }

    // ----- helpers -----

    private static long[] randomBigger(int limbs, long seed)
    {
        long[] dst = new long[limbs];
        long state = seed == 0L ? 1L : seed;
        for (int i = 0; i < limbs; i++)
        {
            state ^= state << 13;
            state ^= state >>> 7;
            state ^= state << 17;
            dst[i] = state;
        }
        return dst;
    }

    /** Same xorshift64 stream as FaestFieldTest, keyed by label for determinism. */
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
        long h = 0xcbf29ce484222325L;
        for (int i = 0; i < label.length(); i++)
        {
            h ^= label.charAt(i);
            h *= 0x100000001b3L;
        }
        return h == 0L ? 1L : h;
    }

    private static void randomLimbs(SecureRandom rng, long[] dst, int limbs)
    {
        byte[] buf = new byte[limbs * 8];
        rng.nextBytes(buf);
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
        runTest(new FaestExtendedFieldTest());
    }
}
