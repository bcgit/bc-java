package org.bouncycastle.pqc.crypto.ntruprime;

import java.util.Random;

import junit.framework.TestCase;

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
