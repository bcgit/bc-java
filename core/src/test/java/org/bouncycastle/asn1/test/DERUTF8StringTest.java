package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class DERUTF8StringTest 
    implements Test
{

    /**
     * Unicode code point U+10400 coded as surrogate in two native Java UTF-16
     * code units
     */
    private final static char[] glyph1_utf16 = { 0xd801, 0xdc00 };

    /**
     * U+10400 coded in UTF-8
     */
    private final static byte[] glyph1_utf8 = { (byte)0xF0, (byte)0x90, (byte)0x90, (byte)0x80 };

    /**
     * Unicode code point U+6771 in native Java UTF-16
     */
    private final static char[] glyph2_utf16 = { 0x6771 };

    /**
     * U+6771 coded in UTF-8
     */
    private final static byte[] glyph2_utf8 = { (byte)0xE6, (byte)0x9D, (byte)0xB1 };

    /**
     * Unicode code point U+00DF in native Java UTF-16
     */
    private final static char[] glyph3_utf16 = { 0x00DF };

    /**
     * U+00DF coded in UTF-8
     */
    private final static byte[] glyph3_utf8 = { (byte)0xC3, (byte)0x9f };

    /**
     * Unicode code point U+0041 in native Java UTF-16
     */
    private final static char[] glyph4_utf16 = { 0x0041 };

    /**
     * U+0041 coded in UTF-8
     */
    private final static byte[] glyph4_utf8 = { 0x41 };

    private final static byte[][] glyphs_utf8 = { glyph1_utf8, glyph2_utf8, glyph3_utf8, glyph4_utf8 };

    private final static char[][] glyphs_utf16 = { glyph1_utf16, glyph2_utf16, glyph3_utf16, glyph4_utf16 };

    public TestResult perform()
    {
        try
        {
            for (int i = 0; i < glyphs_utf16.length; i++)
            {
                String s = new String(glyphs_utf16[i]);
                byte[] b1 = new DERUTF8String(s).getEncoded();
                byte temp[] = new byte[b1.length - 2];
                System.arraycopy(b1, 2, temp, 0, b1.length - 2);
                byte[] b2 = new DERUTF8String(Strings.fromUTF8ByteArray(new DEROctetString(temp).getOctets())).getEncoded();
                if (!Arrays.areEqual(b1, b2))
                {
                    return new SimpleTestResult(false, getName() + ": failed UTF-8 encoding and decoding");
                }
                if (!Arrays.areEqual(temp, glyphs_utf8[i]))
                {
                    return new SimpleTestResult(false, getName() + ": failed UTF-8 encoding and decoding");
                }
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": failed with Exception " + e.getMessage());
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public String getName()
    {
        return "DERUTF8String";
    }

    public static void main(String[] args)
    {
        DERUTF8StringTest test = new DERUTF8StringTest();
        TestResult result = test.perform();

        System.out.println(result);
    }
}
