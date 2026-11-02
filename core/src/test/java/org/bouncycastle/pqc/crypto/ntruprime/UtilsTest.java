package org.bouncycastle.pqc.crypto.ntruprime;

import java.io.ByteArrayOutputStream;
import java.util.Random;

import junit.framework.TestCase;
import org.bouncycastle.util.Arrays;

/**
 * Tests for the arithmetic in NTRU Prime's {@link Utils}.
 * <p>
 * The polynomial products are computed by Karatsuba in int arithmetic and reduced once per coefficient, and
 * getModFreeze() is a multiply-shift reduction, where both used to reduce every partial sum through a division
 * routine. The KATs only reach the inputs their seeds produce, so these tests compare the arithmetic with a plain
 * reference - a schoolbook product in long arithmetic and the % operator - for every parameter set, including the
 * largest operands the callers can pass, which are what the int arithmetic's bounds depend on.
 */
public class UtilsTest
    extends TestCase
{
    // p and q of the six parameter sets, shared by sntrup and ntrulpr
    private static final int[][] PQ = { { 653, 4621 }, { 761, 4591 }, { 857, 5167 }, { 953, 6343 }, { 1013, 7177 },
        { 1277, 7879 } };

    private final Random random = new Random(1);

    public void testModFreeze()
    {
        int[] moduli = { 3, 4591, 4621, 5167, 6343, 7177, 7879 };

        for (int k = 0; k != moduli.length; k++)
        {
            int n = moduli[k];
            long barrett = Utils.getBarrettFactor(n);
            int max = Integer.MAX_VALUE - (n - 1) / 2;

            for (int x = -(1 << 18); x <= (1 << 18); x++)
            {
                checkModFreeze(x, n, barrett);
            }
            for (int i = 0; i < 1000; i++)
            {
                checkModFreeze(Integer.MIN_VALUE + i, n, barrett);
                checkModFreeze(max - i, n, barrett);
            }
            for (int i = 0; i < 200000; i++)
            {
                int x = random.nextInt();
                if (x <= max)
                {
                    checkModFreeze(x, n, barrett);
                }
            }
        }

        assertEquals(Utils.getBarrettFactor(3), Utils.BARRETT_3);
    }

    public void testMultiplicationInRQ()
    {
        for (int k = 0; k != PQ.length; k++)
        {
            int p = PQ[k][0], q = PQ[k][1], half = (q - 1) / 2;

            // the extremes: every coefficient of the reduced factor at +-(q - 1) / 2, the small factor at +-2 (a
            // decoded small polynomial can hold 2), and alternating signs
            int[][] extremes = { { half, 2 }, { -half, 2 }, { half, -2 }, { -half, -2 }, { half, 1 }, { -half, -1 } };
            for (int e = 0; e != extremes.length; e++)
            {
                short[] f = new short[p];
                byte[] g = new byte[p];
                for (int i = 0; i < p; i++)
                {
                    f[i] = (short)extremes[e][0];
                    g[i] = (byte)extremes[e][1];
                }
                checkMultiplicationInRQ(f, g, p, q);

                for (int i = 0; i < p; i += 2)
                {
                    f[i] = (short)-f[i];
                }
                checkMultiplicationInRQ(f, g, p, q);
            }

            for (int trial = 0; trial < 10; trial++)
            {
                short[] f = new short[p];
                byte[] g = new byte[p];
                for (int i = 0; i < p; i++)
                {
                    f[i] = (short)(random.nextInt(q) - half);
                    g[i] = (byte)(random.nextInt(trial < 5 ? 3 : 5) - (trial < 5 ? 1 : 2));
                }
                checkMultiplicationInRQ(f, g, p, q);
            }
        }
    }

    public void testMultiplicationInR3()
    {
        for (int k = 0; k != PQ.length; k++)
        {
            int p = PQ[k][0];

            int[][] extremes = { { 1, 2 }, { -1, 2 }, { 1, -1 }, { -1, -1 } };
            for (int e = 0; e != extremes.length; e++)
            {
                byte[] f = new byte[p];
                byte[] g = new byte[p];
                for (int i = 0; i < p; i++)
                {
                    f[i] = (byte)extremes[e][0];
                    g[i] = (byte)extremes[e][1];
                }
                checkMultiplicationInR3(f, g, p);
            }

            for (int trial = 0; trial < 10; trial++)
            {
                byte[] f = new byte[p];
                byte[] g = new byte[p];
                for (int i = 0; i < p; i++)
                {
                    f[i] = (byte)(random.nextInt(3) - 1);
                    g[i] = (byte)(random.nextInt(4) - 1);
                }
                checkMultiplicationInR3(f, g, p);
            }
        }
    }

    public void testInverseInRQ()
    {
        for (int k = 0; k != PQ.length; k++)
        {
            int q = PQ[k][1], half = (q - 1) / 2;
            for (int x = -half; x <= half; x++)
            {
                int inv = Utils.getInverseInRQ(x, q);
                assertTrue(inv >= -half && inv <= half);
                assertEquals("x = " + x + ", q = " + q, x == 0 ? 0 : 1, centredMod((long)x * inv, q));
            }
        }
    }

    public void testOneThirdInverseInRQ()
    {
        for (int k = 0; k != PQ.length; k++)
        {
            int p = PQ[k][0], q = PQ[k][1];

            // a short polynomial: weight about p / 3, coefficients in {-1, 1}
            byte[] f = new byte[p];
            for (int i = 0; i < p; i++)
            {
                f[i] = (byte)(random.nextInt(3) == 0 ? (random.nextBoolean() ? 1 : -1) : 0);
            }

            short[] finv3 = new short[p];
            Utils.getOneThirdInverseInRQ(finv3, f, p, q);

            // finv3 * 3f = 1
            long[] product = referenceProduct(toInts(finv3), toInts(f), p);
            for (int i = 0; i < p; i++)
            {
                assertEquals("p = " + p + ", coefficient " + i, i == 0 ? 1 : 0, centredMod(3 * product[i], q));
            }
        }
    }

    public void testInvertiblePolynomialInR3()
    {
        for (int k = 0; k != PQ.length; k++)
        {
            int p = PQ[k][0];

            // 0 has no inverse, and the constants 1 and -1 are their own
            byte[] constant = new byte[p];
            byte[] constantInv = new byte[p];
            assertFalse(Utils.isInvertiblePolynomialInR3(constant, constantInv, p));

            for (int c = -1; c <= 1; c += 2)
            {
                constant[0] = (byte)c;
                assertTrue(Utils.isInvertiblePolynomialInR3(constant, constantInv, p));
                assertEquals(c, constantInv[0]);
                for (int i = 1; i < p; i++)
                {
                    assertEquals(0, constantInv[i]);
                }
            }

            int found = 0;
            for (int trial = 0; trial < 4; trial++)
            {
                byte[] g = new byte[p];
                for (int i = 0; i < p; i++)
                {
                    g[i] = (byte)(random.nextInt(3) - 1);
                }

                byte[] ginv = new byte[p];
                if (!Utils.isInvertiblePolynomialInR3(g, ginv, p))
                {
                    continue;
                }
                found++;

                long[] product = referenceProduct(toInts(g), toInts(ginv), p);
                for (int i = 0; i < p; i++)
                {
                    assertEquals("p = " + p + ", coefficient " + i, i == 0 ? 1 : 0, centredMod(product[i], 3));
                }
            }
            assertTrue(found > 0);
        }
    }

    public void testCiphertextDiffMask()
    {
        byte[] a = new byte[1039];
        random.nextBytes(a);
        byte[] b = (byte[])a.clone();

        assertEquals(0, Utils.getCiphertextDiffMask(a, b));
        assertEquals(0, Utils.getCiphertextDiffMask(new byte[0], new byte[0]));

        // every bit of the first, a middle and the last byte, the sign bit included
        int[] positions = { 0, a.length / 2, a.length - 1 };
        for (int k = 0; k != positions.length; k++)
        {
            for (int bit = 0; bit < 8; bit++)
            {
                b[positions[k]] ^= (byte)(1 << bit);
                assertEquals(-1, Utils.getCiphertextDiffMask(a, b));
                b[positions[k]] ^= (byte)(1 << bit);
            }
        }
        assertEquals(0, Utils.getCiphertextDiffMask(a, b));

        byte[] shorter = new byte[a.length - 1];
        System.arraycopy(a, 0, shorter, 0, shorter.length);
        assertEquals(-1, Utils.getCiphertextDiffMask(a, shorter));
        assertEquals(-1, Utils.getCiphertextDiffMask(shorter, a));
    }

    /**
     * Decoding agrees with the reference's Decode, read with unsigned bytes and long arithmetic, for random byte
     * strings, which are mostly non-canonical encodings holding larger bytes than a valid one can, and for valid
     * encodings; encoding agrees with the reference's Encode.
     */
    public void testEncodeDecode()
    {
        for (int k = 0; k != PQ.length; k++)
        {
            int p = PQ[k][0], q = PQ[k][1], half = (q - 1) / 2, m3 = (q + 2) / 3;

            int[] mq = new int[p], mr = new int[p];
            for (int i = 0; i < p; i++)
            {
                mq[i] = q;
                mr[i] = m3;
            }

            for (int trial = 0; trial < 100; trial++)
            {
                // Rq: public keys
                int[] r = new int[p];
                short[] h = new short[p];
                for (int i = 0; i < p; i++)
                {
                    r[i] = trial == 0 ? q - 1 : random.nextInt(q);
                    h[i] = (short)(r[i] - half);
                }
                byte[] expected = referenceEncode(r, mq);
                byte[] enc = new byte[expected.length];
                Utils.getEncodedPolynomial(enc, h, p, q);
                assertTrue("p = " + p, Arrays.areEqual(expected, enc));
                checkDecodedPolynomial(enc, mq, p, q);

                enc = randomBytes(enc.length, trial);
                checkDecodedPolynomial(enc, mq, p, q);

                // rounded: ciphertexts and NTRU LPRime public keys
                for (int i = 0; i < p; i++)
                {
                    r[i] = trial == 0 ? m3 - 1 : random.nextInt(m3);
                    h[i] = (short)(3 * r[i] - half);
                }
                expected = referenceEncode(r, mr);
                enc = new byte[expected.length];
                Utils.getRoundedEncodedPolynomial(enc, h, p, q);
                assertTrue("p = " + p, Arrays.areEqual(expected, enc));
                checkRoundedDecodedPolynomial(enc, mr, p, q);

                enc = randomBytes(enc.length, trial);
                checkRoundedDecodedPolynomial(enc, mr, p, q);
            }
        }
    }

    /**
     * A truncated encoding is rejected rather than decoded with the missing bytes taken as anything.
     */
    public void testDecodeTruncated()
    {
        for (int k = 0; k != PQ.length; k++)
        {
            int p = PQ[k][0], q = PQ[k][1];
            int[] mq = new int[p], mr = new int[p];
            for (int i = 0; i < p; i++)
            {
                mq[i] = q;
                mr[i] = (q + 2) / 3;
            }

            short[] h = new short[p];
            try
            {
                Utils.getDecodedPolynomial(h, new byte[referenceEncode(new int[p], mq).length - 1], p, q);
                fail("p = " + p);
            }
            catch (ArrayIndexOutOfBoundsException e)
            {
                // expected
            }
            try
            {
                Utils.getRoundedDecodedPolynomial(h, new byte[referenceEncode(new int[p], mr).length - 1], p, q);
                fail("p = " + p);
            }
            catch (ArrayIndexOutOfBoundsException e)
            {
                // expected
            }
        }
    }

    private void checkDecodedPolynomial(byte[] enc, int[] m, int p, int q)
    {
        int[] expected = referenceDecode(enc, 0, m);
        short[] h = new short[p];
        Utils.getDecodedPolynomial(h, enc, p, q);
        for (int i = 0; i < p; i++)
        {
            if (h[i] != expected[i] - (q - 1) / 2)
            {
                fail("getDecodedPolynomial p = " + p + ", coefficient " + i + ": " + h[i] + ", expected "
                    + (expected[i] - (q - 1) / 2));
            }
        }
    }

    private void checkRoundedDecodedPolynomial(byte[] enc, int[] m, int p, int q)
    {
        int[] expected = referenceDecode(enc, 0, m);
        short[] h = new short[p];
        Utils.getRoundedDecodedPolynomial(h, enc, p, q);
        for (int i = 0; i < p; i++)
        {
            if (h[i] != 3 * expected[i] - (q - 1) / 2)
            {
                fail("getRoundedDecodedPolynomial p = " + p + ", coefficient " + i + ": " + h[i] + ", expected "
                    + (3 * expected[i] - (q - 1) / 2));
            }
        }
    }

    /**
     * Random bytes, all 0xff on the first trial.
     */
    private byte[] randomBytes(int len, int trial)
    {
        byte[] b = new byte[len];
        if (trial == 0)
        {
            Arrays.fill(b, (byte)0xff);
        }
        else
        {
            random.nextBytes(b);
        }
        return b;
    }

    /**
     * The reference's Encode: r[i] in [0, m[i]).
     */
    private static byte[] referenceEncode(int[] r, int[] m)
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        referenceEncode(out, r, m);
        return out.toByteArray();
    }

    private static void referenceEncode(ByteArrayOutputStream out, int[] r, int[] m)
    {
        int len = r.length;
        if (len == 1)
        {
            long r0 = r[0], m0 = m[0];
            while (m0 > 1)
            {
                out.write((int)r0);
                r0 >>= 8;
                m0 = (m0 + 255) >> 8;
            }
            return;
        }

        int[] r2 = new int[(len + 1) / 2], m2 = new int[(len + 1) / 2];
        int i;
        for (i = 0; i < len - 1; i += 2)
        {
            long ri = r[i] + (long)r[i + 1] * m[i];
            long mi = (long)m[i + 1] * m[i];
            while (mi >= 16384)
            {
                out.write((int)ri);
                ri >>= 8;
                mi = (mi + 255) >> 8;
            }
            r2[i / 2] = (int)ri;
            m2[i / 2] = (int)mi;
        }
        if (i < len)
        {
            r2[i / 2] = r[i];
            m2[i / 2] = m[i];
        }
        referenceEncode(out, r2, m2);
    }

    /**
     * The reference's Decode, for any bytes.
     */
    private static int[] referenceDecode(byte[] s, int sOff, int[] m)
    {
        int len = m.length;
        int[] out = new int[len];
        if (len == 1)
        {
            if (m[0] == 1)
            {
                out[0] = 0;
            }
            else if (m[0] <= 256)
            {
                out[0] = (s[sOff] & 0xff) % m[0];
            }
            else
            {
                out[0] = ((s[sOff] & 0xff) + ((s[sOff + 1] & 0xff) << 8)) % m[0];
            }
            return out;
        }

        int[] m2 = new int[(len + 1) / 2];
        long[] bottomr = new long[len / 2], bottomt = new long[len / 2];
        int i;
        for (i = 0; i < len - 1; i += 2)
        {
            long mi = (long)m[i] * m[i + 1];
            if (mi > 256 * 16383)
            {
                bottomt[i / 2] = 256 * 256;
                bottomr[i / 2] = (s[sOff] & 0xff) + 256 * (s[sOff + 1] & 0xff);
                sOff += 2;
                m2[i / 2] = (int)((((mi + 255) >> 8) + 255) >> 8);
            }
            else if (mi >= 16384)
            {
                bottomt[i / 2] = 256;
                bottomr[i / 2] = s[sOff] & 0xff;
                sOff += 1;
                m2[i / 2] = (int)((mi + 255) >> 8);
            }
            else
            {
                bottomt[i / 2] = 1;
                bottomr[i / 2] = 0;
                m2[i / 2] = (int)mi;
            }
        }
        if (i < len)
        {
            m2[i / 2] = m[i];
        }

        int[] r2 = referenceDecode(s, sOff, m2);
        for (i = 0; i < len - 1; i += 2)
        {
            long r = bottomr[i / 2] + bottomt[i / 2] * r2[i / 2];
            out[i] = (int)(r % m[i]);
            out[i + 1] = (int)((r / m[i]) % m[i + 1]);
        }
        if (i < len)
        {
            out[i] = r2[i / 2];
        }
        return out;
    }

    private static void checkModFreeze(int x, int n, long barrett)
    {
        int expected = centredMod(x, n);
        int actual = Utils.getModFreeze(x, n, barrett);
        if (actual != expected)
        {
            fail("getModFreeze(" + x + ", " + n + ") = " + actual + ", expected " + expected);
        }
    }

    private static void checkMultiplicationInRQ(short[] f, byte[] g, int p, int q)
    {
        short[] h = new short[p];
        Utils.multiplicationInRQ(h, f, g, p, q);

        long[] expected = referenceProduct(toInts(f), toInts(g), p);
        for (int i = 0; i < p; i++)
        {
            if (h[i] != centredMod(expected[i], q))
            {
                fail("multiplicationInRQ p = " + p + ", coefficient " + i + ": " + h[i] + ", expected "
                    + centredMod(expected[i], q));
            }
        }
    }

    private static void checkMultiplicationInR3(byte[] f, byte[] g, int p)
    {
        byte[] h = new byte[p];
        Utils.multiplicationInR3(h, f, g, p);

        long[] expected = referenceProduct(toInts(f), toInts(g), p);
        for (int i = 0; i < p; i++)
        {
            if (h[i] != centredMod(expected[i], 3))
            {
                fail("multiplicationInR3 p = " + p + ", coefficient " + i + ": " + h[i] + ", expected "
                    + centredMod(expected[i], 3));
            }
        }
    }

    /**
     * Schoolbook product modulo x^p - x - 1, exact in long arithmetic.
     */
    private static long[] referenceProduct(int[] f, int[] g, int p)
    {
        long[] fg = new long[2 * p - 1];
        for (int i = 0; i < p; i++)
        {
            for (int j = 0; j < p; j++)
            {
                fg[i + j] += (long)f[i] * g[j];
            }
        }
        for (int i = 2 * p - 2; i >= p; i--)
        {
            fg[i - p] += fg[i];
            fg[i - p + 1] += fg[i];
        }
        return fg;
    }

    /**
     * x mod n in [-(n - 1) / 2, (n - 1) / 2].
     */
    private static int centredMod(long x, int n)
    {
        long r = x % n;
        if (r < 0)
        {
            r += n;
        }
        if (r > (n - 1) / 2)
        {
            r -= n;
        }
        return (int)r;
    }

    private static int[] toInts(short[] s)
    {
        int[] r = new int[s.length];
        for (int i = 0; i < s.length; i++)
        {
            r[i] = s[i];
        }
        return r;
    }

    private static int[] toInts(byte[] b)
    {
        int[] r = new int[b.length];
        for (int i = 0; i < b.length; i++)
        {
            r[i] = b[i];
        }
        return r;
    }
}
