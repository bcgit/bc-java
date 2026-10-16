package org.bouncycastle.util.utiltest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class StringsTest
    extends TestCase
{
    // one character each of the 1, 2, 3 and 4 byte UTF-8 forms
    private static final String UTF8_SAMPLE = new String(new char[]{ 'a', (char)0x00e9, (char)0x20ac, (char)0xd83d, (char)0xde00 });
    private static final byte[] UTF8_SAMPLE_BYTES = Hex.decode("61c3a9e282acf09f9880");

    public void testSplitWithLeadingDelimiter()
    {
        String[] parts = Strings.split(".permitted", '.');
        assertEquals(2, parts.length);
        assertEquals("", parts[0]);
        assertEquals("permitted", parts[1]);
    }

    public void testSplitDomainWithLeadingDot()
    {
        String[] parts = Strings.split(".example.domain.com", '.');
        assertEquals(4, parts.length);
        assertEquals("", parts[0]);
        assertEquals("example", parts[1]);
        assertEquals("domain", parts[2]);
        assertEquals("com", parts[3]);
    }

    public void testSplitNormalDomain()
    {
        String[] parts = Strings.split("example.domain.com", '.');
        assertEquals(3, parts.length);
        assertEquals("example", parts[0]);
        assertEquals("domain", parts[1]);
        assertEquals("com", parts[2]);
    }

    public void testSplitNoDelimiter()
    {
        String[] parts = Strings.split("nodots", '.');
        assertEquals(1, parts.length);
        assertEquals("nodots", parts[0]);
    }

    public void testSplitTrailingDelimiter()
    {
        String[] parts = Strings.split("trailing.", '.');
        assertEquals(2, parts.length);
        assertEquals("trailing", parts[0]);
        assertEquals("", parts[1]);
    }

    public void testSplitOnlyDelimiter()
    {
        String[] parts = Strings.split(".", '.');
        assertEquals(2, parts.length);
        assertEquals("", parts[0]);
        assertEquals("", parts[1]);
    }

    public void testSplitConsecutiveDelimiters()
    {
        String[] parts = Strings.split("a..b", '.');
        assertEquals(3, parts.length);
        assertEquals("a", parts[0]);
        assertEquals("", parts[1]);
        assertEquals("b", parts[2]);
    }

    public void testConstantTimeAreEqual()
    {
        assertTrue(Strings.constantTimeAreEqual("", ""));
        assertTrue(Strings.constantTimeAreEqual("abc", "abc"));
        assertFalse(Strings.constantTimeAreEqual("abc", "abd"));
        assertFalse(Strings.constantTimeAreEqual("abc", "ab"));
        assertFalse(Strings.constantTimeAreEqual("ab", "abc"));
        assertFalse(Strings.constantTimeAreEqual("", "a"));
        // the unequal length branch compares against spaces, which must not turn into a match
        assertFalse(Strings.constantTimeAreEqual("   ", "  "));
    }

    public void testToUTF8()
        throws IOException
    {
        assertTrue(Arrays.areEqual(UTF8_SAMPLE_BYTES, Strings.toUTF8ByteArray(UTF8_SAMPLE)));
        assertEquals(0, Strings.toUTF8ByteArray(new char[0]).length);

        char[] padded = ("xx" + UTF8_SAMPLE + "y").toCharArray();
        assertTrue(Arrays.areEqual(UTF8_SAMPLE_BYTES, Strings.toUTF8ByteArray(padded, 2, UTF8_SAMPLE.length())));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        Strings.toUTF8ByteArray(padded, 2, UTF8_SAMPLE.length(), bOut);
        assertTrue(Arrays.areEqual(UTF8_SAMPLE_BYTES, bOut.toByteArray()));

        // long enough to cross the encoder's internal buffer several times
        StringBuffer sb = new StringBuffer();
        ByteArrayOutputStream expected = new ByteArrayOutputStream();
        for (int i = 0; i != 100; i++)
        {
            sb.append(UTF8_SAMPLE);
            expected.write(UTF8_SAMPLE_BYTES);
        }
        assertTrue(Arrays.areEqual(expected.toByteArray(), Strings.toUTF8ByteArray(sb.toString())));
    }

    public void testToUTF8RejectsBrokenSurrogates()
    {
        checkToUTF8Rejected("\udc00", "invalid UTF-16 high surrogate");
        checkToUTF8Rejected("a\ud800", "invalid UTF-16 codepoint (truncated surrogate pair)");
        checkToUTF8Rejected("\ud800a", "invalid UTF-16 low surrogate");
        checkToUTF8Rejected("\ud800\ud800", "invalid UTF-16 low surrogate");

        // a pair split by the end of the range is truncated, whatever follows the range
        try
        {
            Strings.toUTF8ByteArray(new char[]{ (char)0xd83d, (char)0xde00 }, 0, 1);
            fail("pair split by range accepted");
        }
        catch (IllegalStateException e)
        {
            assertEquals("invalid UTF-16 codepoint (truncated surrogate pair)", e.getMessage());
        }
    }

    public void testFromUTF8()
    {
        assertEquals(UTF8_SAMPLE, Strings.fromUTF8ByteArray(UTF8_SAMPLE_BYTES));
        assertEquals("", Strings.fromUTF8ByteArray(new byte[0]));

        byte[] padded = Arrays.concatenate(Hex.decode("ffff"), UTF8_SAMPLE_BYTES, Hex.decode("ff"));
        assertEquals(UTF8_SAMPLE, Strings.fromUTF8ByteArray(padded, 2, UTF8_SAMPLE_BYTES.length));
    }

    public void testFromUTF8RejectsMalformed()
    {
        checkFromUTF8Rejected("80");          // lone continuation byte
        checkFromUTF8Rejected("c080");        // overlong encoding of U+0000
        checkFromUTF8Rejected("e282");        // truncated 3 byte sequence
        checkFromUTF8Rejected("eda080");      // encoded surrogate U+D800
        checkFromUTF8Rejected("f4908080");    // beyond U+10FFFF
        checkFromUTF8Rejected("ff");
    }

    private static void checkToUTF8Rejected(String s, String message)
    {
        try
        {
            Strings.toUTF8ByteArray(s);
            fail("broken UTF-16 accepted");
        }
        catch (IllegalStateException e)
        {
            assertEquals(message, e.getMessage());
        }
    }

    private static void checkFromUTF8Rejected(String hex)
    {
        byte[] bytes = Hex.decode(hex);
        try
        {
            Strings.fromUTF8ByteArray(bytes);
            fail("malformed UTF-8 accepted: " + hex);
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("Invalid UTF-8 input", e.getMessage());
        }

        byte[] padded = Arrays.concatenate(Hex.decode("61"), bytes, Hex.decode("62"));
        try
        {
            Strings.fromUTF8ByteArray(padded, 1, bytes.length);
            fail("malformed UTF-8 accepted in range: " + hex);
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("Invalid UTF-8 input", e.getMessage());
        }
    }
}
