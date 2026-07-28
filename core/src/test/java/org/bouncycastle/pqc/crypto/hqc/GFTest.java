package org.bouncycastle.pqc.crypto.hqc;

import junit.framework.TestCase;

/**
 * Regression tests for HQC's GF(2^8) arithmetic.
 * <p>
 * {@link GF} used to be implemented with log/exp/inv/sqr lookup tables indexed by field
 * elements, which leaked secret-derived values through the cache; it is now table-free and
 * branch-free. These tests pin the arithmetic to the values the tables produced, so a future
 * change cannot alter a result while the HQC known-answer tests happen to keep passing on the
 * subset of inputs they exercise.
 * <p>
 * The expected values come from an independent construction: log and exp tables built here by
 * iterating the generator X over GF(2)[X]/(X^8 + X^4 + X^3 + X^2 + 1), so the oracle takes a
 * different computational route (discrete logs) from the implementation (carryless multiply and
 * reduce). Field laws are checked as well, in case both sides were to be wrong the same way.
 */
public class GFTest
    extends TestCase
{
    private static final int MODULUS = 0x11D;
    private static final int ORDER = 255;

    private final int[] exp = new int[ORDER];
    private final int[] log = new int[256];

    public void setUp()
    {
        int x = 1;
        for (int i = 0; i < ORDER; ++i)
        {
            exp[i] = x;
            log[x] = i;

            int t = x << 1;
            if ((t & 0x100) != 0)
            {
                t ^= MODULUS;
            }
            x = t & 0xFF;
        }
    }

    /**
     * Guard the oracle itself: these are the opening entries of the classic GF(256) exp table
     * for this field polynomial, and the cycle must close back on 1.
     */
    public void testOracleIsTheExpectedField()
    {
        int[] expected = new int[]{1, 2, 4, 8, 16, 32, 64, 128, 29, 58, 116, 232, 205, 135, 19, 38};
        for (int i = 0; i < expected.length; ++i)
        {
            assertEquals("exp[" + i + "]", expected[i], exp[i]);
        }

        // exp is a bijection onto the 255 non-zero elements, and log inverts it
        boolean[] seen = new boolean[256];
        for (int i = 0; i < ORDER; ++i)
        {
            assertTrue("exp[" + i + "] is zero", exp[i] != 0);
            assertFalse("exp repeats " + exp[i], seen[exp[i]]);
            seen[exp[i]] = true;
            assertEquals("log(exp(" + i + "))", i, log[exp[i]]);
        }
    }

    private int oracleMul(int a, int b)
    {
        if (a == 0 || b == 0)
        {
            return 0;
        }
        return exp[(log[a] + log[b]) % ORDER];
    }

    private int oracleInv(int a)
    {
        if (a == 0)
        {
            return 0;
        }
        return exp[(ORDER - log[a]) % ORDER];
    }

    public void testMulAgainstOracle()
    {
        for (int a = 0; a < 256; ++a)
        {
            for (int b = 0; b < 256; ++b)
            {
                int r = GF.mul(a, b);
                assertEquals("mul(" + a + "," + b + ")", oracleMul(a, b), r);
                assertTrue("mul(" + a + "," + b + ") out of range: " + r, r >= 0 && r < 256);
            }
        }
    }

    public void testSqrAgainstOracle()
    {
        for (int a = 0; a < 256; ++a)
        {
            int r = GF.sqr(a);
            assertEquals("sqr(" + a + ")", oracleMul(a, a), r);
            assertTrue("sqr(" + a + ") out of range: " + r, r >= 0 && r < 256);
        }
    }

    public void testInvAgainstOracle()
    {
        assertEquals("inv(0)", 0, GF.inv(0));

        for (int a = 0; a < 256; ++a)
        {
            int r = GF.inv(a);
            assertEquals("inv(" + a + ")", oracleInv(a), r);
            assertTrue("inv(" + a + ") out of range: " + r, r >= 0 && r < 256);
        }
    }

    public void testDivAgainstOracle()
    {
        for (int a = 0; a < 256; ++a)
        {
            for (int b = 0; b < 256; ++b)
            {
                assertEquals("div(" + a + "," + b + ")", oracleMul(a, oracleInv(b)), GF.div(a, b));
            }
        }
    }

    /**
     * mul3 is exercised on a stride rather than all 16777216 triples, to keep the legacy Ant
     * builds (which run this on a real JRE 1.3/1.4) quick; mul itself is covered exhaustively
     * above and mul3 is defined in terms of it.
     */
    public void testMul3AgainstOracle()
    {
        for (int a = 0; a < 256; a += 5)
        {
            for (int b = 0; b < 256; b += 5)
            {
                for (int c = 0; c < 256; c += 5)
                {
                    int expected = oracleMul(oracleMul(a, b), c);
                    assertEquals("mul3(" + a + "," + b + "," + c + ")", expected, GF.mul3(a, b, c));
                }
            }
        }

        // the zero cases matter: the old implementation masked them explicitly
        for (int a = 0; a < 256; ++a)
        {
            assertEquals("mul3(0," + a + ",1)", 0, GF.mul3(0, a, 1));
            assertEquals("mul3(" + a + ",0,1)", 0, GF.mul3(a, 0, 1));
            assertEquals("mul3(" + a + ",1,0)", 0, GF.mul3(a, 1, 0));
        }
    }

    public void testFieldLaws()
    {
        for (int a = 0; a < 256; ++a)
        {
            assertEquals("mul(" + a + ",0)", 0, GF.mul(a, 0));
            assertEquals("mul(0," + a + ")", 0, GF.mul(0, a));
            assertEquals("mul(" + a + ",1)", a, GF.mul(a, 1));
            assertEquals("mul(1," + a + ")", a, GF.mul(1, a));

            if (a != 0)
            {
                assertEquals("a * inv(a) for a=" + a, 1, GF.mul(a, GF.inv(a)));
                assertEquals("inv(inv(a)) for a=" + a, a, GF.inv(GF.inv(a)));
                assertEquals("div(a,a) for a=" + a, 1, GF.div(a, a));
            }

            for (int b = 0; b < 256; ++b)
            {
                assertEquals("commutativity " + a + "," + b, GF.mul(a, b), GF.mul(b, a));

                if (b != 0)
                {
                    assertEquals("div(mul(a,b),b) for a=" + a + " b=" + b, a, GF.div(GF.mul(a, b), b));
                }
            }
        }

        // distributivity over the additive group (XOR), on a stride
        for (int a = 0; a < 256; a += 3)
        {
            for (int b = 0; b < 256; b += 3)
            {
                for (int c = 0; c < 256; c += 7)
                {
                    assertEquals("distributivity " + a + "," + b + "," + c,
                        GF.mul(a, b ^ c), GF.mul(a, b) ^ GF.mul(a, c));
                }
            }
        }
    }
}
