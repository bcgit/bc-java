package com.github.gv2011.asn1.util;

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


import static com.github.gv2011.util.bytes.ByteUtils.newBytes;
import static com.github.gv2011.util.bytes.ByteUtils.newBytesBuilder;

import java.io.IOException;
import java.io.OutputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Vector;

import com.github.gv2011.util.bytes.Bytes;
import com.github.gv2011.util.bytes.BytesBuilder;

/**
 * String utilities.
 */
public final class Strings
{
    private static String LINE_SEPARATOR;

    static
    {
       try
       {
           LINE_SEPARATOR = AccessController.doPrivileged((PrivilegedAction<String>) () -> System.getProperty("line.separator"));

       }
       catch (final Exception e)
       {
           try
           {
               // the harder way
               LINE_SEPARATOR = String.format("%n");
           }
           catch (final Exception ef)
           {
               LINE_SEPARATOR = "\n";   // we're desperate use this...
           }
       }
    }

    public static String fromUTF8ByteArray(final Bytes bytes)
    {
        int i = 0;
        int length = 0;

        while (i < bytes.size())
        {
            length++;
            if ((bytes.getByte(i) & 0xf0) == 0xf0)
            {
                // surrogate pair
                length++;
                i += 4;
            }
            else if ((bytes.getByte(i) & 0xe0) == 0xe0)
            {
                i += 3;
            }
            else if ((bytes.getByte(i) & 0xc0) == 0xc0)
            {
                i += 2;
            }
            else
            {
                i += 1;
            }
        }

        final char[] cs = new char[length];

        i = 0;
        length = 0;

        while (i < bytes.size())
        {
            char ch;

            if ((bytes.getByte(i) & 0xf0) == 0xf0)
            {
                final int codePoint =
                  ((bytes.getByte(i) & 0x03) << 18) |
                  ((bytes.getByte(i + 1) & 0x3F) << 12) |
                  ((bytes.getByte(i + 2) & 0x3F) << 6) |
                  (bytes.getByte(i + 3) & 0x3F)
                ;
                final int U = codePoint - 0x10000;
                final char W1 = (char)(0xD800 | (U >> 10));
                final char W2 = (char)(0xDC00 | (U & 0x3FF));
                cs[length++] = W1;
                ch = W2;
                i += 4;
            }
            else if ((bytes.getByte(i) & 0xe0) == 0xe0)
            {
                ch = (char)(((bytes.getByte(i) & 0x0f) << 12)
                    | ((bytes.getByte(i + 1) & 0x3f) << 6) | (bytes.getByte(i + 2) & 0x3f));
                i += 3;
            }
            else if ((bytes.getByte(i) & 0xd0) == 0xd0)
            {
                ch = (char)(((bytes.getByte(i) & 0x1f) << 6) | (bytes.getByte(i + 1) & 0x3f));
                i += 2;
            }
            else if ((bytes.getByte(i) & 0xc0) == 0xc0)
            {
                ch = (char)(((bytes.getByte(i) & 0x1f) << 6) | (bytes.getByte(i + 1) & 0x3f));
                i += 2;
            }
            else
            {
                ch = (char)(bytes.getByte(i) & 0xff);
                i += 1;
            }

            cs[length++] = ch;
        }

        return new String(cs);
    }

    public static Bytes toUTF8ByteArray(final String string)
    {
        return toUTF8ByteArray(string.toCharArray());
    }

    public static Bytes toUTF8ByteArray(final char[] string)
    {
        final BytesBuilder bOut = newBytesBuilder();

        try
        {
            toUTF8ByteArray(string, bOut);
        }
        catch (final IOException e)
        {
            throw new IllegalStateException("cannot encode string to byte array!");
        }

        return bOut.build();
    }

    public static void toUTF8ByteArray(final char[] string, final OutputStream sOut)
        throws IOException
    {
        final char[] c = string;
        int i = 0;

        while (i < c.length)
        {
            char ch = c[i];

            if (ch < 0x0080)
            {
                sOut.write(ch);
            }
            else if (ch < 0x0800)
            {
                sOut.write(0xc0 | (ch >> 6));
                sOut.write(0x80 | (ch & 0x3f));
            }
            // surrogate pair
            else if (ch >= 0xD800 && ch <= 0xDFFF)
            {
                // in error - can only happen, if the Java String class has a
                // bug.
                if (i + 1 >= c.length)
                {
                    throw new IllegalStateException("invalid UTF-16 codepoint");
                }
                final char W1 = ch;
                ch = c[++i];
                final char W2 = ch;
                // in error - can only happen, if the Java String class has a
                // bug.
                if (W1 > 0xDBFF)
                {
                    throw new IllegalStateException("invalid UTF-16 codepoint");
                }
                final int codePoint = (((W1 & 0x03FF) << 10) | (W2 & 0x03FF)) + 0x10000;
                sOut.write(0xf0 | (codePoint >> 18));
                sOut.write(0x80 | ((codePoint >> 12) & 0x3F));
                sOut.write(0x80 | ((codePoint >> 6) & 0x3F));
                sOut.write(0x80 | (codePoint & 0x3F));
            }
            else
            {
                sOut.write(0xe0 | (ch >> 12));
                sOut.write(0x80 | ((ch >> 6) & 0x3F));
                sOut.write(0x80 | (ch & 0x3F));
            }

            i++;
        }
    }

    /**
     * A locale independent version of toUpperCase.
     *
     * @param string input to be converted
     * @return a US Ascii uppercase version
     */
    public static String toUpperCase(final String string)
    {
        boolean changed = false;
        final char[] chars = string.toCharArray();

        for (int i = 0; i != chars.length; i++)
        {
            final char ch = chars[i];
            if ('a' <= ch && 'z' >= ch)
            {
                changed = true;
                chars[i] = (char)(ch - 'a' + 'A');
            }
        }

        if (changed)
        {
            return new String(chars);
        }

        return string;
    }

    /**
     * A locale independent version of toLowerCase.
     *
     * @param string input to be converted
     * @return a US ASCII lowercase version
     */
    public static String toLowerCase(final String string)
    {
        boolean changed = false;
        final char[] chars = string.toCharArray();

        for (int i = 0; i != chars.length; i++)
        {
            final char ch = chars[i];
            if ('A' <= ch && 'Z' >= ch)
            {
                changed = true;
                chars[i] = (char)(ch - 'A' + 'a');
            }
        }

        if (changed)
        {
            return new String(chars);
        }

        return string;
    }

    public static byte[] toByteArray(final char[] chars)
    {
        final byte[] bytes = new byte[chars.length];

        for (int i = 0; i != bytes.length; i++)
        {
            bytes[i] = (byte)chars[i];
        }

        return bytes;
    }

    public static Bytes toByteArray(final String string)
    {
        final byte[] bytes = new byte[string.length()];

        for (int i = 0; i != bytes.length; i++)
        {
            final char ch = string.charAt(i);

            bytes[i] = (byte)ch;
        }

        return newBytes(bytes);
    }

    public static int toByteArray(final String s, final byte[] buf, final int off)
    {
        final int count = s.length();
        for (int i = 0; i < count; ++i)
        {
            final char c = s.charAt(i);
            buf[off + i] = (byte)c;
        }
        return count;
    }

    /**
     * Convert an array of 8 bit characters into a string.
     *
     * @param bytes 8 bit characters.
     * @return resulting String.
     */
    public static String fromByteArray(final Bytes bytes)
    {
        return new String(asCharArray(bytes));
    }

    /**
     * Do a simple conversion of an array of 8 bit characters into a string.
     *
     * @param bytes 8 bit characters.
     * @return resulting String.
     */
    public static char[] asCharArray(final Bytes bytes)
    {
        final char[] chars = new char[bytes.size()];

        for (int i = 0; i != chars.length; i++)
        {
            chars[i] = (char)(bytes.getByte(i) & 0xff);
        }

        return chars;
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    public static String[] split(String input, final char delimiter)
    {
        final Vector v = new Vector();
        boolean moreTokens = true;
        String subString;

        while (moreTokens)
        {
            final int tokenLocation = input.indexOf(delimiter);
            if (tokenLocation > 0)
            {
                subString = input.substring(0, tokenLocation);
                v.addElement(subString);
                input = input.substring(tokenLocation + 1);
            }
            else
            {
                moreTokens = false;
                v.addElement(input);
            }
        }

        final String[] res = new String[v.size()];

        for (int i = 0; i != res.length; i++)
        {
            res[i] = (String)v.elementAt(i);
        }
        return res;
    }

    public static StringList newList()
    {
        return new StringListImpl();
    }

    public static String lineSeparator()
    {
        return LINE_SEPARATOR;
    }

    private static class StringListImpl
        extends ArrayList<String>
        implements StringList
    {
      private static final long serialVersionUID = -2942358060595385204L;

        @Override
        public boolean add(final String s)
        {
            return super.add(s);
        }

        @Override
        public String set(final int index, final String element)
        {
            return super.set(index, element);
        }

        @Override
        public void add(final int index, final String element)
        {
            super.add(index, element);
        }

        @Override
        public String[] toStringArray()
        {
            final String[] strs = new String[size()];

            for (int i = 0; i != strs.length; i++)
            {
                strs[i] = get(i);
            }

            return strs;
        }

        @Override
        public String[] toStringArray(final int from, final int to)
        {
            final String[] strs = new String[to - from];

            for (int i = from; i != size() && i != to; i++)
            {
                strs[i - from] = get(i);
            }

            return strs;
        }
    }
}
