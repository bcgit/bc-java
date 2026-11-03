package org.bouncycastle.util.encoders.test;

import java.security.SecureRandom;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.UTF8;
import org.bouncycastle.util.test.SimpleTest;

public class UTF8Test
    extends SimpleTest
{
    private static SecureRandom R = new SecureRandom();

    public String getName()
    {
        return "UTF8";
    }

    public static void main(String[] args)
    {
        runTest(new UTF8Test());
    }

    public void performTest() throws Exception
    {
        for (int i = 0; i < 1000; ++i)
        {
            testBadPrefix2();
            testBadPrefix4();
            testBadSuffix_E0();
            testBadSuffix_ED();
            testBadSuffix_F0();
            testBadSuffix_F4();
            testIncomplete2_1();
            testIncomplete3_1();
            testIncomplete3_2();
            testIncomplete4_1();
            testIncomplete4_2();
            testIncomplete4_3();
            testLeadingSuffix();
            testTruncated2();
            testTruncated3();
            testTruncated4();
            testValid1();
            testValid2();
            testValid3();
            testValid4();
        }

        testLenientUnicodeExample();
        testLenientCases();
        testLenientMatchesStrictOnValid();
        testLenientAgainstJDK();
        testLenientStrings();
    }

    /**
     * The worked example of U+FFFD substitution of maximal subparts in the Unicode Standard, ch. 3.
     */
    private static final byte[] UNICODE_EXAMPLE = new byte[]{ 0x61, (byte)0xF1, (byte)0x80, (byte)0x80,
        (byte)0xE1, (byte)0x80, (byte)0xC2, 0x62, (byte)0x80, 0x63, (byte)0x80, (byte)0xBF, 0x64 };
    private static final String UNICODE_EXAMPLE_DECODED = "a\ufffd\ufffd\ufffdb\ufffdc\ufffd\ufffdd";

    private void testLenientUnicodeExample()
    {
        isEquals("Unicode maximal subpart example", UNICODE_EXAMPLE_DECODED, lenient(UNICODE_EXAMPLE));
    }

    private void testLenientCases()
    {
        // lone continuation byte, and bytes that can never appear
        isEquals("lone continuation", "a\ufffdb", lenient(new byte[]{ 'a', (byte)0x80, 'b' }));
        isEquals("C0/C1/F5..FF", "\ufffd\ufffd\ufffd\ufffd",
            lenient(new byte[]{ (byte)0xC0, (byte)0xC1, (byte)0xF5, (byte)0xFF }));
        // a sequence broken by an ASCII byte keeps the ASCII byte
        isEquals("Latin-1 e-acute", "caf\ufffd.txt",
            lenient(new byte[]{ 'c', 'a', 'f', (byte)0xE9, '.', 't', 'x', 't' }));
        // overlong and surrogate encodings fail at their second byte, so each byte is replaced
        isEquals("overlong NUL", "\ufffd\ufffd", lenient(new byte[]{ (byte)0xC0, (byte)0x80 }));
        isEquals("overlong 3-byte", "\ufffd\ufffd\ufffd", lenient(new byte[]{ (byte)0xE0, (byte)0x80, (byte)0xAF }));
        // ED may only be followed by 80..9F (Unicode Table 3-7), so an encoded surrogate is three maximal subparts;
        // the JDK decoder gives one U+FFFD here, which is why compareWithJDK() skips this pattern
        isEquals("surrogate", "\ufffd\ufffd\ufffd", lenient(new byte[]{ (byte)0xED, (byte)0xA0, (byte)0x80 }));
        isEquals("surrogate pair", "\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd",
            lenient(new byte[]{ (byte)0xED, (byte)0xA0, (byte)0x80, (byte)0xED, (byte)0xBF, (byte)0xBF }));
        isEquals("truncated surrogate", "\ufffd\ufffd", lenient(new byte[]{ (byte)0xED, (byte)0xA0 }));
        isEquals("ED in range, truncated", "\ufffd", lenient(new byte[]{ (byte)0xED, (byte)0x9F }));
        isEquals("above U+10FFFF", "\ufffd\ufffd\ufffd\ufffd",
            lenient(new byte[]{ (byte)0xF4, (byte)0x90, (byte)0x80, (byte)0x80 }));
        // truncated by the end of the input: one replacement for the whole partial sequence
        isEquals("truncated 4-byte", "x\ufffd", lenient(new byte[]{ 'x', (byte)0xF0, (byte)0x9F, (byte)0x98 }));
        // a valid sequence after a broken one is decoded
        isEquals("broken then valid", "\ufffd\u00e9",
            lenient(new byte[]{ (byte)0xE2, (byte)0x82, (byte)0xC3, (byte)0xA9 }));
        isEquals("empty", "", lenient(new byte[0]));

        // the output array is still only checked for room, never for validity
        isEquals("lenient, output too small", -1,
            UTF8.transcodeToUTF16(new byte[]{ (byte)0x80, (byte)0x80 }, 0, 2, new char[1], true));
        // strict mode is unchanged
        isEquals("strict still fails", -1, UTF8.transcodeToUTF16(UNICODE_EXAMPLE, new char[UNICODE_EXAMPLE.length]));
    }

    private void testLenientMatchesStrictOnValid()
    {
        for (int i = 0; i < 2000; ++i)
        {
            char[] chars = new char[R.nextInt(32)];
            for (int c = 0; c < chars.length; ++c)
            {
                int cp;
                do
                {
                    cp = R.nextInt(0x110000);
                }
                while (cp >= 0xD800 && cp <= 0xDFFF);
                if (cp > 0xFFFF)
                {
                    // keep the char[] the same length by writing a BMP character instead of a pair
                    cp &= 0xFFFF;
                    if (cp >= 0xD800 && cp <= 0xDFFF)
                    {
                        cp = 'z';
                    }
                }
                chars[c] = (char)cp;
            }
            byte[] utf8 = Strings.toUTF8ByteArray(chars);

            char[] strict = new char[utf8.length];
            char[] lenient = new char[utf8.length];
            int sLen = UTF8.transcodeToUTF16(utf8, 0, utf8.length, strict, false);
            int lLen = UTF8.transcodeToUTF16(utf8, 0, utf8.length, lenient, true);

            isEquals("valid input: same length", sLen, lLen);
            isTrue("valid input: same output", new String(strict, 0, sLen).equals(new String(lenient, 0, lLen)));
        }
    }

    private void testLenientAgainstJDK()
        throws Exception
    {
        // only a JDK implementing maximal-subpart replacement is a reference, which means Java 8 on: earlier
        // decoders can pass the Unicode example yet still accept overlong forms such as C0 80
        String specVersion = System.getProperty("java.specification.version", "1.0");
        if ((specVersion.startsWith("1.") && !specVersion.equals("1.8"))
            || !UNICODE_EXAMPLE_DECODED.equals(new String(UNICODE_EXAMPLE, "UTF-8")))
        {
            return;
        }

        // every two-byte input
        byte[] two = new byte[2];
        for (int i = 0; i < 0x10000; ++i)
        {
            two[0] = (byte)(i >> 8);
            two[1] = (byte)i;
            compareWithJDK(two);
        }

        // random short inputs weighted towards lead and continuation bytes
        byte[] interesting = new byte[]{ 0x00, 0x41, 0x7F, (byte)0x80, (byte)0x8F, (byte)0x90, (byte)0x9F,
            (byte)0xA0, (byte)0xBF, (byte)0xC0, (byte)0xC1, (byte)0xC2, (byte)0xDF, (byte)0xE0, (byte)0xE1,
            (byte)0xEC, (byte)0xED, (byte)0xEE, (byte)0xEF, (byte)0xF0, (byte)0xF1, (byte)0xF3, (byte)0xF4,
            (byte)0xF5, (byte)0xFF };
        for (int i = 0; i < 100000; ++i)
        {
            byte[] utf8 = new byte[1 + R.nextInt(8)];
            for (int b = 0; b < utf8.length; ++b)
            {
                utf8[b] = R.nextInt(4) == 0 ? (byte)R.nextInt(256) : interesting[R.nextInt(interesting.length)];
            }
            compareWithJDK(utf8);
        }
    }

    private void compareWithJDK(byte[] utf8)
        throws Exception
    {
        // the JDK replaces an encoded surrogate (ED A0..BF ..) as a single unit, which is not maximal-subpart
        // replacement; those inputs are checked against the standard in testLenientCases() instead
        for (int i = 0; i + 1 < utf8.length; ++i)
        {
            if ((utf8[i] & 0xFF) == 0xED && (utf8[i + 1] & 0xFF) >= 0xA0 && (utf8[i + 1] & 0xFF) <= 0xBF)
            {
                return;
            }
        }

        String expected = new String(utf8, "UTF-8");
        String actual = lenient(utf8);
        if (!expected.equals(actual))
        {
            fail("lenient decode differs from JDK for " + org.bouncycastle.util.encoders.Hex.toHexString(utf8));
        }
    }

    private void testLenientStrings()
    {
        byte[] bad = new byte[]{ 'a', (byte)0xFF, 'b' };

        isEquals("Strings lenient", "a\ufffdb", Strings.fromUTF8ByteArray(bad, true));
        isEquals("Strings lenient, offset", "\ufffdb", Strings.fromUTF8ByteArray(bad, 1, 2, true));
        try
        {
            Strings.fromUTF8ByteArray(bad, false);
            fail("strict Strings decode should reject malformed input");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("Invalid UTF-8 input", e.getMessage());
        }
    }

    private static String lenient(byte[] utf8)
    {
        char[] utf16 = new char[utf8.length];
        int len = UTF8.transcodeToUTF16(utf8, 0, utf8.length, utf16, true);
        if (len < 0)
        {
            throw new IllegalStateException("lenient decode returned -1 with an output array the size of the input");
        }
        return new String(utf16, 0, len);
    }

    private void testBadPrefix2()
    {
        byte[] utf8 = new byte[2];
        char[] utf16 = new char[1];

        for (int i = 0x00; i < 0x02; ++i)
        {
            utf8[0] = (byte)(0xC0 | i);
            utf8[1] = randomSuffix();
            utf16[0] = (char)0;

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testBadPrefix2", result, -1);
        }
    }

    private void testBadPrefix4()
    {
        byte[] utf8 = new byte[4];
        char[] utf16 = new char[2];

        for (int i = 0x05; i < 0x0F; ++i)
        {
            utf8[0] = (byte)(0xF0 | i);
            utf8[1] = randomSuffix();
            utf8[2] = randomSuffix();
            utf8[3] = randomSuffix();
            utf16[0] = (char)0;
            utf16[1] = (char)0;

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testBadPrefix4", result, -1);
        }
        
    }

    private void testBadSuffix_E0()
    {
        byte[] utf8 = new byte[3];
        char[] utf16 = new char[1];

        utf8[0] = (byte)0xE0;
        utf8[1] = randomSuffix();
        utf8[2] = randomSuffix();
        utf16[0] = (char)0;

        utf8[1] &= 0x9F;

        int result = UTF8.transcodeToUTF16(utf8, utf16);

        isEquals("testBadSuffix_E0", result, -1);
    }

    private void testBadSuffix_ED()
    {
        byte[] utf8 = new byte[3];
        char[] utf16 = new char[1];

        utf8[0] = (byte)0xED;
        utf8[1] = randomSuffix();
        utf8[2] = randomSuffix();
        utf16[0] = (char)0;

        utf8[1] |= 0x20; 

        int result = UTF8.transcodeToUTF16(utf8, utf16);

        isEquals("testBadSuffix_ED", result, -1);
    }

    private void testBadSuffix_F0()
    {
        byte[] utf8 = new byte[4];
        char[] utf16 = new char[2];

        utf8[0] = (byte)0xF0;
        utf8[1] = randomSuffix();
        utf8[2] = randomSuffix();
        utf8[3] = randomSuffix();
        utf16[0] = (char)0;
        utf16[1] = (char)0;

        utf8[1] &= 0x8F;

        int result = UTF8.transcodeToUTF16(utf8, utf16);

        isEquals("testBadSuffix_F0", result, -1);
    }

    private void testBadSuffix_F4()
    {
        byte[] utf8 = new byte[4];
        char[] utf16 = new char[2];

        utf8[0] = (byte)0xF4;
        utf8[1] = randomSuffix();
        utf8[2] = randomSuffix();
        utf8[3] = randomSuffix();
        utf16[0] = (char)0;
        utf16[1] = (char)0;

        utf8[1] |= 0x10 << (R.nextInt() & 1);

        int result = UTF8.transcodeToUTF16(utf8, utf16);

        isEquals("testBadSuffix_F4", result, -1);
    }

    private void testIncomplete2_1()
    {
        byte[] utf8 = new byte[2];
        char[] utf16 = new char[1];

        for (int i = 0x02; i < 0x20; ++i)
        {
            utf8[0] = (byte)(0xC0 | i);
            utf8[1] = randomPrefix();
            utf16[0] = (char)0xFFFF;

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testIncomplete2_1", result, -1);
        }
    }

    private void testIncomplete3_1()
    {
        byte[] utf8 = new byte[3];
        char[] utf16 = new char[1];

        for (int i = 0x00; i < 0x10; ++i)
        {
            utf8[0] = (byte)(0xE0 | i);
            utf8[1] = randomPrefix();
            utf8[2] = randomSuffix();
            utf16[0] = (char)0xFFFF;

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testIncomplete3_1", result, -1);
        }
    }

    private void testIncomplete3_2()
    {
        byte[] utf8 = new byte[3];
        char[] utf16 = new char[1];

        for (int i = 0x00; i < 0x10; ++i)
        {
            utf8[0] = (byte)(0xE0 | i);
            utf8[1] = randomSuffix();
            utf8[2] = randomPrefix();
            utf16[0] = (char)0;

            if (i == 0x00)
            {
                utf8[1] |= 0x20; 
            }
            else if (i == 0x0D)
            {
                utf8[1] &= 0x9F;
            }

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testIncomplete3_2", result, -1);
        }
        
    }

    private void testIncomplete4_1()
    {
        byte[] utf8 = new byte[4];
        char[] utf16 = new char[2];

        for (int i = 0x00; i < 0x05; ++i)
        {
            utf8[0] = (byte)(0xF0 | i);
            utf8[1] = randomPrefix();
            utf8[2] = randomSuffix();
            utf8[3] = randomSuffix();
            utf16[0] = (char)0;
            utf16[1] = (char)0;

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testIncomplete4_1", result, -1);
        }
    }
    
    private void testIncomplete4_2()
    {
        byte[] utf8 = new byte[4];
        char[] utf16 = new char[2];

        for (int i = 0x00; i < 0x05; ++i)
        {
            utf8[0] = (byte)(0xF0 | i);
            utf8[1] = randomSuffix();
            utf8[2] = randomPrefix();
            utf8[3] = randomSuffix();
            utf16[0] = (char)0;
            utf16[1] = (char)0;

            if (i == 0x00)
            {
                utf8[1] |= 0x10 << (R.nextInt() & 1);
            }
            else if (i == 0x04)
            {
                utf8[1] &= 0x8F;
            }

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testIncomplete4_2", result, -1);
        }
    }
    
    private void testIncomplete4_3()
    {
        byte[] utf8 = new byte[4];
        char[] utf16 = new char[2];

        for (int i = 0x00; i < 0x05; ++i)
        {
            utf8[0] = (byte)(0xF0 | i);
            utf8[1] = randomSuffix();
            utf8[2] = randomSuffix();
            utf8[3] = randomPrefix();
            utf16[0] = (char)0;
            utf16[1] = (char)0;

            if (i == 0x00)
            {
                utf8[1] |= 0x10 << (R.nextInt() & 1);
            }
            else if (i == 0x04)
            {
                utf8[1] &= 0x8F;
            }

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testIncomplete4_3", result, -1);
        }
    }

    private void testLeadingSuffix()
    {
        byte[] utf8 = new byte[4];
        char[] utf16 = new char[4];

        for (int i = 0x80; i < 0xC0; ++i)
        {
            utf8[0] = (byte)i;
            utf8[1] = randomSuffix();
            utf8[2] = randomSuffix();
            utf8[3] = randomSuffix();

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testLeadingSuffix", result, -1);
        }
    }

    private void testTruncated2()
    {
        byte[] utf8 = new byte[2];
        char[] utf16 = new char[1];

        for (int i = 0x02; i < 0x20; ++i)
        {
            utf8[0] = (byte)(0xC0 | i);
            utf8[1] = randomSuffix();
            utf16[0] = (char)0;

            // Use truncated length with otherwise valid UTF8
            int result = UTF8.transcodeToUTF16(utf8, 0, 1, utf16);

            isEquals("testTruncated2", result, -1);
        }
    }

    private void testTruncated3()
    {
        byte[] utf8 = new byte[3];
        char[] utf16 = new char[1];

        for (int i = 0x00; i < 0x10; ++i)
        {
            utf8[0] = (byte)(0xE0 | i);
            utf8[1] = randomSuffix();
            utf8[2] = randomSuffix();
            utf16[0] = (char)0;

            if (i == 0x00)
            {
                utf8[1] |= 0x20; 
            }
            else if (i == 0x0D)
            {
                utf8[1] &= 0x9F;
            }

            // Use truncated length with otherwise valid UTF8
            int result = UTF8.transcodeToUTF16(utf8, 0, 2, utf16);

            isEquals("testTruncated3", result, -1);
        }
    }

    private void testTruncated4()
    {
        byte[] utf8 = new byte[4];
        char[] utf16 = new char[2];

        for (int i = 0x00; i < 0x05; ++i)
        {
            utf8[0] = (byte)(0xF0 | i);
            utf8[1] = randomSuffix();
            utf8[2] = randomSuffix();
            utf8[3] = randomSuffix();
            utf16[0] = (char)0;
            utf16[1] = (char)0;

            if (i == 0x00)
            {
                utf8[1] |= 0x10 << (R.nextInt() & 1);
            }
            else if (i == 0x04)
            {
                utf8[1] &= 0x8F;
            }

            // Use truncated length with otherwise valid UTF8
            int result = UTF8.transcodeToUTF16(utf8, 0, 3, utf16);

            isEquals("testTruncated4", result, -1);
        }
    }

    private void testValid1()
    {
        byte[] utf8 = new byte[1];
        char[] utf16 = new char[1];

        for (int i = 0x00; i < 0x80; ++i)
        {
            utf8[0] = (byte)i;
            utf16[0] = (char)0xFFFF;

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testValid1.Result", result, 1);
            isEquals("testValid1.Value", utf16[0], i);
        }
    }

    private void testValid2()
    {
        byte[] utf8 = new byte[2];
        char[] utf16 = new char[1];

        for (int i = 0x02; i < 0x20; ++i)
        {
            utf8[0] = (byte)(0xC0 | i);
            utf8[1] = randomSuffix();
            utf16[0] = (char)0;

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testValid2.Result", result, 1);
            isEquals("testValid2.Value", utf16[0], (i << 6) | (utf8[1] & 0x3F));
        }
    }

    private void testValid3()
    {
        byte[] utf8 = new byte[3];
        char[] utf16 = new char[1];

        for (int i = 0x00; i < 0x10; ++i)
        {
            utf8[0] = (byte)(0xE0 | i);
            utf8[1] = randomSuffix();
            utf8[2] = randomSuffix();
            utf16[0] = (char)0;

            if (i == 0x00)
            {
                utf8[1] |= 0x20; 
            }
            else if (i == 0x0D)
            {
                utf8[1] &= 0x9F;
            }

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testValid3.Result", result, 1);
            isEquals("testValid3.Value", utf16[0], (i << 12) | ((utf8[1] & 0x3F) << 6) | (utf8[2] & 0x3F));
        }
    }

    private void testValid4()
    {
        byte[] utf8 = new byte[4];
        char[] utf16 = new char[2];

        for (int i = 0x00; i < 0x05; ++i)
        {
            utf8[0] = (byte)(0xF0 | i);
            utf8[1] = randomSuffix();
            utf8[2] = randomSuffix();
            utf8[3] = randomSuffix();
            utf16[0] = (char)0;
            utf16[1] = (char)0;

            if (i == 0x00)
            {
                utf8[1] |= 0x10 << (R.nextInt() & 1);
            }
            else if (i == 0x04)
            {
                utf8[1] &= 0x8F;
            }

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testValid4.Result", result, 2);
            isEquals("testValid4.Value",
                ((utf16[0] - 0xD7C0) << 10) | (utf16[1] - 0xDC00),
                (i << 18) | ((utf8[1] & 0x3F) << 12) | ((utf8[2] & 0x3F) << 6) | (utf8[3] & 0x3F));
        }
    }

    private byte randomInRange(byte lo, byte hi)
    {
        int a = lo & 0xFF, b = hi & 0xFF, d = b - a;

        return (byte)(lo + ((R.nextInt() >>> 1) % d));
    }

    private byte randomPrefix()
    {
        switch ((R.nextInt() & 3) + 1)
        {
        case 2:
            return randomInRange((byte)0xC2, (byte)0xE0);
        case 3:
            return randomInRange((byte)0xE0, (byte)0xF0);
        case 4:
            return randomInRange((byte)0xF0, (byte)0xF6);
        default:
            return (byte)(R.nextInt() & 0x7F);
        }
    }

    private byte randomSuffix()
    {
        return (byte)((R.nextInt() >>> 26) | 0x80);
    }
}
