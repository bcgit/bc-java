package org.bouncycastle.pqc.crypto.hqc;

import junit.framework.TestCase;

/**
 * Tests for HQC's GF(2^8) arithmetic.
 * <p>
 * {@link GF} forwards to {@code GF256AES}, whose arithmetic is tested exhaustively in
 * {@code GF256AESTest}. These tests pin what is HQC's own: that the field is the one of the HQC
 * specification of 2026-10-12, and that the composition {@link GF#div} is right, including on
 * zero.
 */
public class GFTest
    extends TestCase
{
    /**
     * The reduction X^8 = X^4 + X^3 + X + 1, and the opening entries of the reference
     * implementation's gf_exp, the powers of the generator X + 1, which must have order 255 (X
     * alone is not primitive in this field, its order is 51).
     */
    public void testFieldIsTheSpecField()
    {
        assertEquals("X^7 * X", 0x1B, GF.mul(0x80, 0x02));

        int[] expected = new int[]{ 1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53 };
        int x = 1;
        for (int i = 0; i < expected.length; ++i)
        {
            assertEquals("gf_exp[" + i + "]", expected[i], x);
            x = GF.mul(x, 0x03);
        }

        x = 1;
        for (int i = 1; i <= 255; ++i)
        {
            x = GF.mul(x, 0x03);
            assertEquals("(X + 1)^" + i + " == 1", i == 255, x == 1);
        }
    }

    public void testDivInvertsMul()
    {
        for (int a = 0; a < 256; ++a)
        {
            // the inverse of zero is defined as zero, so division by zero yields zero
            assertEquals("div(" + a + ",0)", 0, GF.div(a, 0));

            for (int b = 1; b < 256; ++b)
            {
                int q = GF.div(a, b);
                assertTrue("div(" + a + "," + b + ") out of range: " + q, q >= 0 && q < 256);
                assertEquals("mul(div(a,b),b) for a=" + a + " b=" + b, a, GF.mul(q, b));
            }
        }
    }
}
