package org.bouncycastle.openpgp.wot.internal;

import java.util.Collections;
import java.util.Iterator;

public class Util
{
    private Util()
    {
    }

    public static byte[] longToBytes(final long value)
    {
        final byte[] bytes = new byte[8];
        longToBytes(value, bytes, 0);
        return bytes;
    }

    public static void longToBytes(final long value, final byte[] bytes, final int index)
    {
        assertNotNull("bytes", bytes);
        if (bytes.length - index < 8)
            throw new IllegalArgumentException("bytes.length - index < 8");

        for (int i = 0; i < 8; ++i)
            bytes[index + i] = (byte) (value >>> (8 * (8 - 1 - i)));
    }

    public static long bytesToLong(final byte[] bytes)
    {
        assertNotNull("bytes", bytes);
        if (bytes.length != 8)
            throw new IllegalArgumentException("bytes.length != 8");

        return bytesToLong(bytes, 0);
    }

    public static long bytesToLong(final byte[] bytes, final int index)
    {
        assertNotNull("bytes", bytes);
        if (bytes.length - index < 8)
            throw new IllegalArgumentException("bytes.length - index < 8");

        long value = 0;
        for (int i = 0; i < 8; ++i)
            value |= ((long) (bytes[index + i] & 0xff)) << (8 * (8 - 1 - i));

        return value;
    }

    public static byte[] intToBytes(final int value)
    {
        final byte[] bytes = new byte[4];
        intToBytes(value, bytes, 0);
        return bytes;
    }

    public static void intToBytes(final int value, final byte[] bytes, final int index)
    {
        assertNotNull("bytes", bytes);
        if (bytes.length - index < 4)
            throw new IllegalArgumentException("bytes.length - index < 4");

        for (int i = 0; i < 4; ++i)
            bytes[index + i] = (byte) (value >>> (8 * (4 - 1 - i)));
    }

    public static int bytesToInt(final byte[] bytes)
    {
        assertNotNull("bytes", bytes);
        if (bytes.length != 4)
            throw new IllegalArgumentException("bytes.length != 4");

        return bytesToInt(bytes, 0);
    }

    public static int bytesToInt(final byte[] bytes, final int index)
    {
        assertNotNull("bytes", bytes);
        if (bytes.length - index < 4)
            throw new IllegalArgumentException("bytes.length - index < 4");

        int value = 0;
        for (int i = 0; i < 4; ++i)
            value |= ((long) (bytes[index + i] & 0xff)) << (8 * (4 - 1 - i));

        return value;
    }

    public static String encodeHexStr(final byte[] buf)
    {
        return encodeHexStr(buf, 0, buf.length);
    }

    /**
     * Encode a byte array into a human readable hex string. For each byte, two hex digits are produced. They are
     * concatenated without any separators.
     *
     * @param buf
     *            The byte array to translate into human readable text.
     * @param pos
     *            The start position (0-based).
     * @param len
     *            The number of bytes that shall be processed beginning at the position specified by <code>pos</code>.
     * @return a human readable string like "fa3d70" for a byte array with 3 bytes and these values.
     * @see #encodeHexStr(byte[])
     * @see #decodeHexStr(String)
     */
    public static String encodeHexStr(final byte[] buf, int pos, int len)
    {
        final StringBuilder hex = new StringBuilder();
        while (len-- > 0)
        {
            final byte ch = buf[pos++];
            int d = (ch >> 4) & 0xf;
            hex.append((char) (d >= 10 ? 'a' - 10 + d : '0' + d));
            d = ch & 0xf;
            hex.append((char) (d >= 10 ? 'a' - 10 + d : '0' + d));
        }
        return hex.toString();
    }

    /**
     * Decode a string containing two hex digits for each byte.
     *
     * @param hex
     *            The hex encoded string
     * @return The byte array represented by the given hex string
     * @see #encodeHexStr(byte[])
     * @see #encodeHexStr(byte[], int, int)
     */
    public static byte[] decodeHexStr(final String hex)
    {
        if (hex.length() % 2 != 0)
            throw new IllegalArgumentException("The hex string must have an even number of characters!");

        final byte[] res = new byte[hex.length() / 2];

        int m = 0;
        for (int i = 0; i < hex.length(); i += 2)
        {
            res[m++] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }

        return res;
    }

    public static final <T> T assertNotNull(final String name, final T object)
    {
        if (object == null)
            throw new IllegalArgumentException(String.format("%s == null", name));

        return object;
    }

    public static <E> Iterator<E> nullToEmpty(final Iterator<E> iterator)
    {
        if (iterator == null)
            return Collections.<E> emptyList().iterator();
        else
            return iterator;
    }

    public static final void doNothing()
    {
    }
}
