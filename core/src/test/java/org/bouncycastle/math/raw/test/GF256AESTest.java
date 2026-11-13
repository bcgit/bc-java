package org.bouncycastle.math.raw.test;

import org.bouncycastle.math.raw.GF256AES;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Exhaustive tests of {@link GF256AES} against an independent oracle: log and exp tables built
 * here by iterating the generator X + 1 over GF(2)[X]/(X^8 + X^4 + X^3 + X + 1). The oracle takes
 * a different computational route (discrete logs) from the implementation (carryless multiply and
 * reduce), and field laws are checked as well, in case both sides were to be wrong the same way.
 */
public class GF256AESTest
    extends TestCase
{
    private static final int MODULUS = 0x11B;
    private static final int ORDER = 255;

    private static final int[] EXP = new int[ORDER];
    private static final int[] LOG = new int[256];

    static
    {
        int x = 1;
        for (int i = 0; i < ORDER; ++i)
        {
            EXP[i] = x;
            LOG[x] = i;

            // multiply by the generator X + 1
            int t = (x << 1) ^ x;
            if ((t & 0x100) != 0)
            {
                t ^= MODULUS;
            }
            x = t & 0xFF;
        }
    }

    private static int oracleMul(int a, int b)
    {
        if (a == 0 || b == 0)
        {
            return 0;
        }
        return EXP[(LOG[a] + LOG[b]) % ORDER];
    }

    private static int oracleInv(int a)
    {
        if (a == 0)
        {
            return 0;
        }
        return EXP[(ORDER - LOG[a]) % ORDER];
    }

    /**
     * Guard the oracle itself: these are the opening entries of the exp table for this field
     * polynomial and generator, and the cycle must close back on 1.
     */
    public void testOracleIsTheExpectedField()
    {
        int[] expected = new int[]{ 1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53 };
        for (int i = 0; i < expected.length; ++i)
        {
            assertEquals("exp[" + i + "]", expected[i], EXP[i]);
        }

        // exp is a bijection onto the 255 non-zero elements, and log inverts it
        boolean[] seen = new boolean[256];
        for (int i = 0; i < ORDER; ++i)
        {
            assertTrue("exp[" + i + "] is zero", EXP[i] != 0);
            assertFalse("exp repeats " + EXP[i], seen[EXP[i]]);
            seen[EXP[i]] = true;
            assertEquals("log(exp(" + i + "))", i, LOG[EXP[i]]);
        }
    }

    /**
     * Published values: the FIPS 197 multiplication examples (Sections 4.2 and 4.2.1), and the
     * inverse pair {53}, {CA}. Checked against both the oracle and the implementation.
     */
    public void testKnownValues()
    {
        assertEquals("oracle {57}*{83}", 0xC1, oracleMul(0x57, 0x83));
        assertEquals("{57}*{83}", 0xC1, GF256AES.mul(0x57, 0x83));
        assertEquals("oracle {57}*{13}", 0xFE, oracleMul(0x57, 0x13));
        assertEquals("{57}*{13}", 0xFE, GF256AES.mul(0x57, 0x13));
        assertEquals("oracle inv({53})", 0xCA, oracleInv(0x53));
        assertEquals("inv({53})", 0xCA, GF256AES.inv(0x53));
    }

    public void testMulAgainstOracle()
    {
        for (int a = 0; a < 256; ++a)
        {
            for (int b = 0; b < 256; ++b)
            {
                int r = GF256AES.mul(a, b);
                assertEquals("mul(" + a + "," + b + ")", oracleMul(a, b), r);
                assertTrue("mul(" + a + "," + b + ") out of range: " + r, r >= 0 && r < 256);
            }
        }
    }

    public void testSqrAgainstOracle()
    {
        for (int a = 0; a < 256; ++a)
        {
            int r = GF256AES.sqr(a);
            assertEquals("sqr(" + a + ")", oracleMul(a, a), r);
            assertTrue("sqr(" + a + ") out of range: " + r, r >= 0 && r < 256);
        }
    }

    public void testInvAgainstOracle()
    {
        for (int a = 0; a < 256; ++a)
        {
            int r = GF256AES.inv(a);
            assertEquals("inv(" + a + ")", oracleInv(a), r);
            assertTrue("inv(" + a + ") out of range: " + r, r >= 0 && r < 256);
        }
    }

    /**
     * Only the low 8 bits of each argument are used, whatever the high bits (including the sign)
     * hold.
     */
    public void testHighBitsIgnored()
    {
        int[] highs = new int[]{ 0x100, 0x7FFFFF00, ~0xFF, Integer.MIN_VALUE };
        for (int i = 0; i < highs.length; ++i)
        {
            int h = highs[i];
            for (int a = 0; a < 256; ++a)
            {
                assertEquals("sqr(" + h + "|" + a + ")", GF256AES.sqr(a), GF256AES.sqr(h | a));
                assertEquals("inv(" + h + "|" + a + ")", GF256AES.inv(a), GF256AES.inv(h | a));

                for (int b = 0; b < 256; b += 7)
                {
                    assertEquals("mul(" + h + "|" + a + "," + h + "|" + b + ")",
                        GF256AES.mul(a, b), GF256AES.mul(h | a, h | b));
                }
            }
        }
    }

    public void testFieldLaws()
    {
        for (int a = 0; a < 256; ++a)
        {
            assertEquals("mul(" + a + ",0)", 0, GF256AES.mul(a, 0));
            assertEquals("mul(0," + a + ")", 0, GF256AES.mul(0, a));
            assertEquals("mul(" + a + ",1)", a, GF256AES.mul(a, 1));
            assertEquals("mul(1," + a + ")", a, GF256AES.mul(1, a));

            if (a != 0)
            {
                assertEquals("a * inv(a) for a=" + a, 1, GF256AES.mul(a, GF256AES.inv(a)));
                assertEquals("inv(inv(a)) for a=" + a, a, GF256AES.inv(GF256AES.inv(a)));
            }

            for (int b = 0; b < 256; ++b)
            {
                assertEquals("commutativity " + a + "," + b, GF256AES.mul(a, b), GF256AES.mul(b, a));

                if (b != 0)
                {
                    assertEquals("mul(mul(a,b),inv(b)) for a=" + a + " b=" + b,
                        a, GF256AES.mul(GF256AES.mul(a, b), GF256AES.inv(b)));
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
                        GF256AES.mul(a, b) ^ GF256AES.mul(a, c), GF256AES.mul(a, b ^ c));
                }
            }
        }
    }

    /**
     * Every lane of {@link GF256AES#mulFx8(int, long)} agrees with {@link GF256AES#mul(int, int)},
     * for every scalar and lane value, with each value visiting every lane, and whatever the high
     * bits of the scalar hold.
     */
    public void testMulFx8AgainstMul()
    {
        int[] highs = new int[]{ 0, 0x100, ~0xFF, Integer.MIN_VALUE };
        for (int i = 0; i < highs.length; ++i)
        {
            for (int s = 0; s < 256; ++s)
            {
                for (int rot = 0; rot < 8; ++rot)
                {
                    for (int base = 0; base < 256; base += 8)
                    {
                        long v = 0;
                        for (int lane = 0; lane < 8; ++lane)
                        {
                            v |= ((long)(base + ((lane + rot) & 7))) << (8 * lane);
                        }

                        long p = GF256AES.mulFx8(highs[i] | s, v);
                        for (int lane = 0; lane < 8; ++lane)
                        {
                            int x = (int)(v >>> (8 * lane)) & 0xFF;
                            assertEquals("mulFx8(" + (highs[i] | s) + ") lane " + lane + " x=" + x,
                                GF256AES.mul(s, x), (int)(p >>> (8 * lane)) & 0xFF);
                        }
                    }
                }
            }
        }
    }

    public static Test suite()
    {
        return new TestSuite(GF256AESTest.class);
    }
}
