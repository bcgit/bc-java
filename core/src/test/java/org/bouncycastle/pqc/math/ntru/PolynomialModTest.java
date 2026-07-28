package org.bouncycastle.pqc.math.ntru;

import junit.framework.TestCase;

/**
 * Regression tests for NTRU's modular reductions.
 * <p>
 * {@link Polynomial#mod3(short)}, {@link Polynomial#mod3(byte)} and
 * {@link Polynomial#modQ(int, int)} used to be written with the {@code %} operator, which
 * compiles to an integer division whose latency depends on its operands - and all three run on
 * secret data (the secret key polynomials f and g, the message polynomials r and m, and the
 * coefficients recovered during decapsulation). They are now division-free, matching the
 * reference implementation, and these tests pin them to the values {@code %} produced across the
 * entire input domain that reaches them.
 * <p>
 * This test has to live in {@code org.bouncycastle.pqc.math.ntru} rather than the
 * {@code ...ntru.test} package alongside {@link org.bouncycastle.pqc.math.ntru.test.PolynomialTest},
 * because the methods are package-private.
 */
public class PolynomialModTest
    extends TestCase
{
    /**
     * Every logQ appearing in a parameter set: NTRUHPS2048509/677 use 11, NTRUHPS4096821/1229
     * use 12, NTRUHRSS701 uses 13 and NTRUHRSS1373 uses 14. NTRUParameterSet.q() is 1 << logQ,
     * which is what makes masking a valid reduction.
     */
    private static final int[] LOG_QS = new int[]{11, 12, 13, 14};

    public void testMod3ShortOverEveryInput()
    {
        for (int a = Short.MIN_VALUE; a <= Short.MAX_VALUE; ++a)
        {
            short s = (short)a;
            assertEquals("mod3(short " + s + ")", (s & 0xffff) % 3, Polynomial.mod3(s));
        }
    }

    public void testMod3ByteOverEveryInput()
    {
        for (int a = Byte.MIN_VALUE; a <= Byte.MAX_VALUE; ++a)
        {
            byte b = (byte)a;
            assertEquals("mod3(byte " + b + ")", (byte)((b & 0xff) % 3), Polynomial.mod3(b));
        }
    }

    /**
     * The callers treat the result as a ternary coefficient, so nothing may escape 0..2 - the
     * masked conditional subtraction has to leave the folded value fully reduced.
     */
    public void testMod3IsAlwaysTernary()
    {
        for (int a = Short.MIN_VALUE; a <= Short.MAX_VALUE; ++a)
        {
            short r = Polynomial.mod3((short)a);
            assertTrue("mod3(short " + a + ") = " + r, r >= 0 && r <= 2);
        }

        for (int a = Byte.MIN_VALUE; a <= Byte.MAX_VALUE; ++a)
        {
            byte r = Polynomial.mod3((byte)a);
            assertTrue("mod3(byte " + a + ") = " + r, r >= 0 && r <= 2);
        }
    }

    /**
     * Every call site passes a dividend already masked to 16 bits, so that is the domain that
     * has to agree with {@code %}; q is a power of two for every parameter set.
     */
    public void testModQOverEveryInputAndParameterSet()
    {
        for (int i = 0; i < LOG_QS.length; ++i)
        {
            int q = 1 << LOG_QS[i];
            for (int x = 0; x <= 0xffff; ++x)
            {
                assertEquals("modQ(" + x + ", " + q + ")", x % q, Polynomial.modQ(x, q));
            }
        }
    }

    public void testModQIsInRange()
    {
        for (int i = 0; i < LOG_QS.length; ++i)
        {
            int q = 1 << LOG_QS[i];
            for (int x = 0; x <= 0xffff; ++x)
            {
                int r = Polynomial.modQ(x, q);
                assertTrue("modQ(" + x + ", " + q + ") = " + r, r >= 0 && r < q);
            }
        }
    }
}
