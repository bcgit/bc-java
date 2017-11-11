package com.github.gv2011.asn1;

/*-
 * #%L
 * Vinz ASN.1
 * %%
 * Copyright (C) 2016 - 2017 Vinz (https://github.com/gv2011)
 * %%
 * Please note this should be read in the same way as the MIT license. (https://www.bouncycastle.org/licence.html)
 * 
 * Copyright (c) 2000-2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
 * and associated documentation files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 * #L%
 */


import static com.github.gv2011.testutil.Matchers.hasClass;
import static com.github.gv2011.testutil.Matchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Test;

import com.github.gv2011.asn1.dump.ASN1Dump;
import com.github.gv2011.asn1.util.Arrays;
import com.github.gv2011.asn1.util.Strings;
import com.github.gv2011.asn1.util.test.LegacyTest;
import com.github.gv2011.asn1.util.test.SimpleTestResult;
import com.github.gv2011.asn1.util.test.TestResult;
import com.github.gv2011.util.bytes.ByteUtils;
import com.github.gv2011.util.bytes.Bytes;

public class DERUTF8StringTest implements LegacyTest{
  
  @Test
  public void testRoundTrip() {
    final DERUTF8String asn1 = new DERUTF8String("test");
    final Bytes encoded = asn1.getDerEncoded();
    final ASN1Primitive back = ASN1InputStream.parse(encoded);
    assertThat(back, is(asn1));
    assertThat(back, hasClass(DERUTF8String.class));
    final DERTaggedObject tagged = new DERTaggedObject(false, 7, asn1);
    System.out.println(ASN1Dump.dumpAsString(tagged, true));
  }

  @Test
  public void test() {
    main(new String[0]);
  }

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

    @Override
    public TestResult perform()
    {
        try
        {
            for (int i = 0; i < glyphs_utf16.length; i++)
            {
                final String s = new String(glyphs_utf16[i]);
                final byte[] b1 = new DERUTF8String(s).getEncoded().toByteArray();
                final byte temp[] = new byte[b1.length - 2];
                System.arraycopy(b1, 2, temp, 0, b1.length - 2);
                final byte[] b2 = new DERUTF8String(Strings.fromUTF8ByteArray(
                  new DEROctetString(ByteUtils.newBytes(temp)).getOctets()
                )).getEncoded().toByteArray();
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
        catch (final Exception e)
        {
            return new SimpleTestResult(false, getName() + ": failed with Exception " + e.getMessage());
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    @Override
    public String getName()
    {
        return "DERUTF8String";
    }

    public static void main(final String[] args)
    {
        final DERUTF8StringTest test = new DERUTF8StringTest();
        final TestResult result = test.perform();

        System.out.println(result);
    }
}
