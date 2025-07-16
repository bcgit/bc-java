package org.bouncycastle.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Vector;

import org.bouncycastle.util.encoders.UTF8;

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
            LINE_SEPARATOR = AccessController.doPrivileged(new PrivilegedAction<String>()
            {
                public String run()
                {
                    // the easy way
                    return System.getProperty("line.separator");
                }
            });

        }
        catch (Exception e)
        {
            try
            {
                // the harder way
                LINE_SEPARATOR = String.format("%n");
            }
            catch (Exception ef)
            {
                LINE_SEPARATOR = "\n";   // we're desperate use this...
            }
        }
    }

    public static String fromUTF8ByteArray(byte[] bytes)
    {
        return fromUTF8ByteArray(bytes, 0, bytes.length);
    }

    public static String fromUTF8ByteArray(byte[] bytes, int off, int length)
    {
        char[] chars = new char[length];
        int len = UTF8.transcodeToUTF16(bytes, off, length, chars);
        if (len < 0)
        {
            throw new IllegalArgumentException("Invalid UTF-8 input");
        }
        return new String(chars, 0, len);
    }

    public static byte[] toUTF8ByteArray(String string)
    {
        return toUTF8ByteArray(string.toCharArray());
    }

    public static byte[] toUTF8ByteArray(char[] string)
    {
        return toUTF8ByteArray(string, 0, string.length);
    }

    public static byte[] toUTF8ByteArray(char[] cs, int csOff, int csLen)
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        try
        {
            toUTF8ByteArray(cs, csOff, csLen, bOut);
        }
        catch (IOException e)
        {
            throw new IllegalStateException("cannot encode string to byte array!");
        }

        return bOut.toByteArray();
    }

    public static void toUTF8ByteArray(char[] string, OutputStream sOut)
        throws IOException
    {
        toUTF8ByteArray(string, 0, string.length, sOut);
    }

    public static void toUTF8ByteArray(char[] cs, int csOff, int csLen, OutputStream sOut)
            throws IOException
    {
        if (csLen < 1)
        {
            return;
        }

        byte[] buf = new byte[64];

        int bufPos = 0, i = 0;
        do
        {
            int c = cs[csOff + i++];

            if (c < 0x0080)
            {
                buf[bufPos++] = (byte)c;
            }
            else if (c < 0x0800)
            {
                buf[bufPos++] = (byte)(0xC0 | (c >> 6));
                buf[bufPos++] = (byte)(0x80 | (c & 0x3F));
            }
            // surrogate pair
            else if (c >= 0xD800 && c <= 0xDFFF)
            {
                /*
                 * Various checks that shouldn't fail unless the Java String class has a bug.
                 */
                int W1 = c;
                if (W1 > 0xDBFF)
                {
                    throw new IllegalStateException("invalid UTF-16 high surrogate");
                }

                if (i >= csLen)
                {
                    throw new IllegalStateException("invalid UTF-16 codepoint (truncated surrogate pair)");
                }

                int W2 = cs[csOff + i++];
                if (W2 < 0xDC00 || W2 > 0xDFFF)
                {
                    throw new IllegalStateException("invalid UTF-16 low surrogate");
                }

                int codePoint = (((W1 & 0x03FF) << 10) | (W2 & 0x03FF)) + 0x10000;
                buf[bufPos++] = (byte)(0xF0 | (codePoint >> 18));
                buf[bufPos++] = (byte)(0x80 | ((codePoint >> 12) & 0x3F));
                buf[bufPos++] = (byte)(0x80 | ((codePoint >> 6) & 0x3F));
                buf[bufPos++] = (byte)(0x80 | (codePoint & 0x3F));
            }
            else
            {
                buf[bufPos++] = (byte)(0xE0 | (c >> 12));
                buf[bufPos++] = (byte)(0x80 | ((c >> 6) & 0x3F));
                buf[bufPos++] = (byte)(0x80 | (c & 0x3F));
            }

            if (bufPos + 4 > buf.length)
            {
                sOut.write(buf, 0, bufPos);
                bufPos = 0;
            }
        }
        while (i < csLen);

        if (bufPos > 0)
        {
            sOut.write(buf, 0, bufPos);
//            bufPos = 0;
        }
    }

    /**
     * A locale independent version of toUpperCase.
     *
     * @param string input to be converted
     * @return a US Ascii uppercase version
     */
    public static String toUpperCase(String string)
    {
        boolean changed = false;
        char[] chars = string.toCharArray();

        for (int i = 0; i != chars.length; i++)
        {
            char ch = chars[i];
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
    public static String toLowerCase(String string)
    {
        boolean changed = false;
        char[] chars = string.toCharArray();

        for (int i = 0; i != chars.length; i++)
        {
            char ch = chars[i];
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

    public static byte[] toByteArray(char[] chars)
    {
        byte[] bytes = new byte[chars.length];

        for (int i = 0; i != bytes.length; i++)
        {
            bytes[i] = (byte)chars[i];
        }

        return bytes;
    }


    public static byte[] toByteArray(String string)
    {
        byte[] bytes = new byte[string.length()];

        for (int i = 0; i != bytes.length; i++)
        {
            char ch = string.charAt(i);

            bytes[i] = (byte)ch;
        }

        return bytes;
    }

    public static int toByteArray(String s, byte[] buf, int off)
    {
        int count = s.length();
        for (int i = 0; i < count; ++i)
        {
            char c = s.charAt(i);
            buf[off + i] = (byte)c;
        }
        return count;
    }

    /**
     * Constant time string comparison.
     *
     * @param a a string.
     * @param b another string to compare to a.
     *
     * @return true if a and b represent the same string, false otherwise.
     */
    public static boolean constantTimeAreEqual(String a, String b)
    {
        boolean isEqual = a.length() == b.length();
        int     len = a.length();

        if (isEqual)
        {
            for (int i = 0; i != len; i++)
            {
                isEqual &= (a.charAt(i) == b.charAt(i));
            }
        }
        else
        {
            for (int i = 0; i != len; i++)
            {
                isEqual &= (a.charAt(i) == ' ');
            }
        }

        return isEqual;
    }

    /**
     * Convert an array of 8 bit characters into a string.
     *
     * @param bytes 8 bit characters.
     * @return resulting String.
     */
    public static String fromByteArray(byte[] bytes)
    {
        return new String(asCharArray(bytes));
    }

    /**
     * Do a simple conversion of an array of 8 bit characters into a string.
     *
     * @param bytes 8 bit characters.
     * @return resulting String.
     */
    public static char[] asCharArray(byte[] bytes)
    {
        char[] chars = new char[bytes.length];

        for (int i = 0; i != chars.length; i++)
        {
            chars[i] = (char)(bytes[i] & 0xff);
        }

        return chars;
    }

    public static String[] split(String input, char delimiter)
    {
        Vector v = new Vector();
        boolean moreTokens = true;
        String subString;

        while (moreTokens)
        {
            int tokenLocation = input.indexOf(delimiter);
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

        String[] res = new String[v.size()];

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
        public boolean add(String s)
        {
            return super.add(s);
        }

        public String set(int index, String element)
        {
            return super.set(index, element);
        }

        public void add(int index, String element)
        {
            super.add(index, element);
        }

        public String[] toStringArray()
        {
            String[] strs = new String[this.size()];

            for (int i = 0; i != strs.length; i++)
            {
                strs[i] = this.get(i);
            }

            return strs;
        }

        public String[] toStringArray(int from, int to)
        {
            String[] strs = new String[to - from];

            for (int i = from; i != this.size() && i != to; i++)
            {
                strs[i - from] = this.get(i);
            }

            return strs;
        }
    }
}
