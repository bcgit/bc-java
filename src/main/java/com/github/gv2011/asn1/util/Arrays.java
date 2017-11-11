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


import java.math.BigInteger;
import java.util.NoSuchElementException;

/**
 * General array utilities.
 */
public final class Arrays
{
    private Arrays()
    {
        // static class, hide constructor
    }

    public static boolean areEqual(
        final boolean[]  a,
        final boolean[]  b)
    {
        if (a == b)
        {
            return true;
        }

        if (a == null || b == null)
        {
            return false;
        }

        if (a.length != b.length)
        {
            return false;
        }

        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    public static boolean areEqual(
        final char[]  a,
        final char[]  b)
    {
        if (a == b)
        {
            return true;
        }

        if (a == null || b == null)
        {
            return false;
        }

        if (a.length != b.length)
        {
            return false;
        }

        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    public static boolean areEqual(
        final byte[]  a,
        final byte[]  b)
    {
        if (a == b)
        {
            return true;
        }

        if (a == null || b == null)
        {
            return false;
        }

        if (a.length != b.length)
        {
            return false;
        }

        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    /**
     * A constant time equals comparison - does not terminate early if
     * test will fail.
     *
     * @param a first array
     * @param b second array
     * @return true if arrays equal, false otherwise.
     */
    public static boolean constantTimeAreEqual(
        final byte[]  a,
        final byte[]  b)
    {
        if (a == b)
        {
            return true;
        }

        if (a == null || b == null)
        {
            return false;
        }

        if (a.length != b.length)
        {
            return false;
        }

        int nonEqual = 0;

        for (int i = 0; i != a.length; i++)
        {
            nonEqual |= (a[i] ^ b[i]);
        }

        return nonEqual == 0;
    }

    public static boolean areEqual(
        final int[]  a,
        final int[]  b)
    {
        if (a == b)
        {
            return true;
        }

        if (a == null || b == null)
        {
            return false;
        }

        if (a.length != b.length)
        {
            return false;
        }

        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    public static boolean areEqual(
        final long[]  a,
        final long[]  b)
    {
        if (a == b)
        {
            return true;
        }

        if (a == null || b == null)
        {
            return false;
        }

        if (a.length != b.length)
        {
            return false;
        }

        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    public static boolean areEqual(final Object[] a, final Object[] b)
    {
        if (a == b)
        {
            return true;
        }
        if (a == null || b == null)
        {
            return false;
        }
        if (a.length != b.length)
        {
            return false;
        }
        for (int i = 0; i != a.length; i++)
        {
            final Object objA = a[i], objB = b[i];
            if (objA == null)
            {
                if (objB != null)
                {
                    return false;
                }
            }
            else if (!objA.equals(objB))
            {
                return false;
            }
        }
        return true;
    }

    public static boolean contains(final short[] a, final short n)
    {
        for (int i = 0; i < a.length; ++i)
        {
            if (a[i] == n)
            {
                return true;
            }
        }
        return false;
    }

    public static boolean contains(final int[] a, final int n)
    {
        for (int i = 0; i < a.length; ++i)
        {
            if (a[i] == n)
            {
                return true;
            }
        }
        return false;
    }

    public static void fill(
        final byte[] array,
        final byte value)
    {
        for (int i = 0; i < array.length; i++)
        {
            array[i] = value;
        }
    }

    public static void fill(
        final char[] array,
        final char value)
    {
        for (int i = 0; i < array.length; i++)
        {
            array[i] = value;
        }
    }

    public static void fill(
        final long[] array,
        final long value)
    {
        for (int i = 0; i < array.length; i++)
        {
            array[i] = value;
        }
    }

    public static void fill(
        final short[] array,
        final short value)
    {
        for (int i = 0; i < array.length; i++)
        {
            array[i] = value;
        }
    }

    public static void fill(
        final int[] array,
        final int value)
    {
        for (int i = 0; i < array.length; i++)
        {
            array[i] = value;
        }
    }

    public static int hashCode(final byte[] data)
    {
        if (data == null)
        {
            return 0;
        }

        int i = data.length;
        int hc = i + 1;

        while (--i >= 0)
        {
            hc *= 257;
            hc ^= data[i];
        }

        return hc;
    }

    public static int hashCode(final byte[] data, final int off, final int len)
    {
        if (data == null)
        {
            return 0;
        }

        int i = len;
        int hc = i + 1;

        while (--i >= 0)
        {
            hc *= 257;
            hc ^= data[off + i];
        }

        return hc;
    }

    public static int hashCode(final char[] data)
    {
        if (data == null)
        {
            return 0;
        }

        int i = data.length;
        int hc = i + 1;

        while (--i >= 0)
        {
            hc *= 257;
            hc ^= data[i];
        }

        return hc;
    }

    public static int hashCode(final int[][] ints)
    {
        int hc = 0;

        for (int i = 0; i != ints.length; i++)
        {
            hc = hc * 257 + hashCode(ints[i]);
        }

        return hc;
    }

    public static int hashCode(final int[] data)
    {
        if (data == null)
        {
            return 0;
        }

        int i = data.length;
        int hc = i + 1;

        while (--i >= 0)
        {
            hc *= 257;
            hc ^= data[i];
        }

        return hc;
    }

    public static int hashCode(final int[] data, final int off, final int len)
    {
        if (data == null)
        {
            return 0;
        }

        int i = len;
        int hc = i + 1;

        while (--i >= 0)
        {
            hc *= 257;
            hc ^= data[off + i];
        }

        return hc;
    }

    public static int hashCode(final long[] data)
    {
        if (data == null)
        {
            return 0;
        }

        int i = data.length;
        int hc = i + 1;

        while (--i >= 0)
        {
            final long di = data[i];
            hc *= 257;
            hc ^= (int)di;
            hc *= 257;
            hc ^= (int)(di >>> 32);
        }

        return hc;
    }

    public static int hashCode(final long[] data, final int off, final int len)
    {
        if (data == null)
        {
            return 0;
        }

        int i = len;
        int hc = i + 1;

        while (--i >= 0)
        {
            final long di = data[off + i];
            hc *= 257;
            hc ^= (int)di;
            hc *= 257;
            hc ^= (int)(di >>> 32);
        }

        return hc;
    }

    public static int hashCode(final short[][][] shorts)
    {
        int hc = 0;

        for (int i = 0; i != shorts.length; i++)
        {
            hc = hc * 257 + hashCode(shorts[i]);
        }

        return hc;
    }

    public static int hashCode(final short[][] shorts)
    {
        int hc = 0;

        for (int i = 0; i != shorts.length; i++)
        {
            hc = hc * 257 + hashCode(shorts[i]);
        }

        return hc;
    }

    public static int hashCode(final short[] data)
    {
        if (data == null)
        {
            return 0;
        }

        int i = data.length;
        int hc = i + 1;

        while (--i >= 0)
        {
            hc *= 257;
            hc ^= (data[i] & 0xff);
        }

        return hc;
    }

    public static int hashCode(final Object[] data)
    {
        if (data == null)
        {
            return 0;
        }

        int i = data.length;
        int hc = i + 1;

        while (--i >= 0)
        {
            hc *= 257;
            hc ^= data[i].hashCode();
        }

        return hc;
    }

    public static byte[] clone(final byte[] data)
    {
        if (data == null)
        {
            return null;
        }
        final byte[] copy = new byte[data.length];

        System.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    public static char[] clone(final char[] data)
    {
        if (data == null)
        {
            return null;
        }
        final char[] copy = new char[data.length];

        System.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    public static byte[] clone(final byte[] data, final byte[] existing)
    {
        if (data == null)
        {
            return null;
        }
        if ((existing == null) || (existing.length != data.length))
        {
            return clone(data);
        }
        System.arraycopy(data, 0, existing, 0, existing.length);
        return existing;
    }

    public static byte[][] clone(final byte[][] data)
    {
        if (data == null)
        {
            return null;
        }

        final byte[][] copy = new byte[data.length][];

        for (int i = 0; i != copy.length; i++)
        {
            copy[i] = clone(data[i]);
        }

        return copy;
    }

    public static byte[][][] clone(final byte[][][] data)
    {
        if (data == null)
        {
            return null;
        }

        final byte[][][] copy = new byte[data.length][][];

        for (int i = 0; i != copy.length; i++)
        {
            copy[i] = clone(data[i]);
        }

        return copy;
    }

    public static int[] clone(final int[] data)
    {
        if (data == null)
        {
            return null;
        }
        final int[] copy = new int[data.length];

        System.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    public static long[] clone(final long[] data)
    {
        if (data == null)
        {
            return null;
        }
        final long[] copy = new long[data.length];

        System.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    public static long[] clone(final long[] data, final long[] existing)
    {
        if (data == null)
        {
            return null;
        }
        if ((existing == null) || (existing.length != data.length))
        {
            return clone(data);
        }
        System.arraycopy(data, 0, existing, 0, existing.length);
        return existing;
    }

    public static short[] clone(final short[] data)
    {
        if (data == null)
        {
            return null;
        }
        final short[] copy = new short[data.length];

        System.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    public static BigInteger[] clone(final BigInteger[] data)
    {
        if (data == null)
        {
            return null;
        }
        final BigInteger[] copy = new BigInteger[data.length];

        System.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    public static byte[] copyOf(final byte[] data, final int newLength)
    {
        final byte[] tmp = new byte[newLength];

        if (newLength < data.length)
        {
            System.arraycopy(data, 0, tmp, 0, newLength);
        }
        else
        {
            System.arraycopy(data, 0, tmp, 0, data.length);
        }

        return tmp;
    }

    public static char[] copyOf(final char[] data, final int newLength)
    {
        final char[] tmp = new char[newLength];

        if (newLength < data.length)
        {
            System.arraycopy(data, 0, tmp, 0, newLength);
        }
        else
        {
            System.arraycopy(data, 0, tmp, 0, data.length);
        }

        return tmp;
    }

    public static int[] copyOf(final int[] data, final int newLength)
    {
        final int[] tmp = new int[newLength];

        if (newLength < data.length)
        {
            System.arraycopy(data, 0, tmp, 0, newLength);
        }
        else
        {
            System.arraycopy(data, 0, tmp, 0, data.length);
        }

        return tmp;
    }

    public static long[] copyOf(final long[] data, final int newLength)
    {
        final long[] tmp = new long[newLength];

        if (newLength < data.length)
        {
            System.arraycopy(data, 0, tmp, 0, newLength);
        }
        else
        {
            System.arraycopy(data, 0, tmp, 0, data.length);
        }

        return tmp;
    }

    public static BigInteger[] copyOf(final BigInteger[] data, final int newLength)
    {
        final BigInteger[] tmp = new BigInteger[newLength];

        if (newLength < data.length)
        {
            System.arraycopy(data, 0, tmp, 0, newLength);
        }
        else
        {
            System.arraycopy(data, 0, tmp, 0, data.length);
        }

        return tmp;
    }

    /**
     * Make a copy of a range of bytes from the passed in data array. The range can
     * extend beyond the end of the input array, in which case the return array will
     * be padded with zeroes.
     *
     * @param data the array from which the data is to be copied.
     * @param from the start index at which the copying should take place.
     * @param to the final index of the range (exclusive).
     *
     * @return a new byte array containing the range given.
     */
    public static byte[] copyOfRange(final byte[] data, final int from, final int to)
    {
        final int newLength = getLength(from, to);

        final byte[] tmp = new byte[newLength];

        if (data.length - from < newLength)
        {
            System.arraycopy(data, from, tmp, 0, data.length - from);
        }
        else
        {
            System.arraycopy(data, from, tmp, 0, newLength);
        }

        return tmp;
    }

    public static int[] copyOfRange(final int[] data, final int from, final int to)
    {
        final int newLength = getLength(from, to);

        final int[] tmp = new int[newLength];

        if (data.length - from < newLength)
        {
            System.arraycopy(data, from, tmp, 0, data.length - from);
        }
        else
        {
            System.arraycopy(data, from, tmp, 0, newLength);
        }

        return tmp;
    }

    public static long[] copyOfRange(final long[] data, final int from, final int to)
    {
        final int newLength = getLength(from, to);

        final long[] tmp = new long[newLength];

        if (data.length - from < newLength)
        {
            System.arraycopy(data, from, tmp, 0, data.length - from);
        }
        else
        {
            System.arraycopy(data, from, tmp, 0, newLength);
        }

        return tmp;
    }

    public static BigInteger[] copyOfRange(final BigInteger[] data, final int from, final int to)
    {
        final int newLength = getLength(from, to);

        final BigInteger[] tmp = new BigInteger[newLength];

        if (data.length - from < newLength)
        {
            System.arraycopy(data, from, tmp, 0, data.length - from);
        }
        else
        {
            System.arraycopy(data, from, tmp, 0, newLength);
        }

        return tmp;
    }

    private static int getLength(final int from, final int to)
    {
        final int newLength = to - from;
        if (newLength < 0)
        {
            final StringBuffer sb = new StringBuffer(from);
            sb.append(" > ").append(to);
            throw new IllegalArgumentException(sb.toString());
        }
        return newLength;
    }

    public static byte[] append(final byte[] a, final byte b)
    {
        if (a == null)
        {
            return new byte[]{ b };
        }

        final int length = a.length;
        final byte[] result = new byte[length + 1];
        System.arraycopy(a, 0, result, 0, length);
        result[length] = b;
        return result;
    }

    public static short[] append(final short[] a, final short b)
    {
        if (a == null)
        {
            return new short[]{ b };
        }

        final int length = a.length;
        final short[] result = new short[length + 1];
        System.arraycopy(a, 0, result, 0, length);
        result[length] = b;
        return result;
    }

    public static int[] append(final int[] a, final int b)
    {
        if (a == null)
        {
            return new int[]{ b };
        }

        final int length = a.length;
        final int[] result = new int[length + 1];
        System.arraycopy(a, 0, result, 0, length);
        result[length] = b;
        return result;
    }

    public static byte[] concatenate(final byte[] a, final byte[] b)
    {
        if (a != null && b != null)
        {
            final byte[] rv = new byte[a.length + b.length];

            System.arraycopy(a, 0, rv, 0, a.length);
            System.arraycopy(b, 0, rv, a.length, b.length);

            return rv;
        }
        else if (b != null)
        {
            return clone(b);
        }
        else
        {
            return clone(a);
        }
    }

    public static byte[] concatenate(final byte[] a, final byte[] b, final byte[] c)
    {
        if (a != null && b != null && c != null)
        {
            final byte[] rv = new byte[a.length + b.length + c.length];

            System.arraycopy(a, 0, rv, 0, a.length);
            System.arraycopy(b, 0, rv, a.length, b.length);
            System.arraycopy(c, 0, rv, a.length + b.length, c.length);

            return rv;
        }
        else if (a == null)
        {
            return concatenate(b, c);
        }
        else if (b == null)
        {
            return concatenate(a, c);
        }
        else
        {
            return concatenate(a, b);
        }
    }

    public static byte[] concatenate(final byte[] a, final byte[] b, final byte[] c, final byte[] d)
    {
        if (a != null && b != null && c != null && d != null)
        {
            final byte[] rv = new byte[a.length + b.length + c.length + d.length];

            System.arraycopy(a, 0, rv, 0, a.length);
            System.arraycopy(b, 0, rv, a.length, b.length);
            System.arraycopy(c, 0, rv, a.length + b.length, c.length);
            System.arraycopy(d, 0, rv, a.length + b.length + c.length, d.length);

            return rv;
        }
        else if (d == null)
        {
            return concatenate(a, b, c);
        }
        else if (c == null)
        {
            return concatenate(a, b, d);
        }
        else if (b == null)
        {
            return concatenate(a, c, d);
        }
        else
        {
            return concatenate(b, c, d);
        }
    }

    public static int[] concatenate(final int[] a, final int[] b)
    {
        if (a == null)
        {
            return clone(b);
        }
        if (b == null)
        {
            return clone(a);
        }

        final int[] c = new int[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    public static byte[] prepend(final byte[] a, final byte b)
    {
        if (a == null)
        {
            return new byte[]{ b };
        }

        final int length = a.length;
        final byte[] result = new byte[length + 1];
        System.arraycopy(a, 0, result, 1, length);
        result[0] = b;
        return result;
    }

    public static short[] prepend(final short[] a, final short b)
    {
        if (a == null)
        {
            return new short[]{ b };
        }

        final int length = a.length;
        final short[] result = new short[length + 1];
        System.arraycopy(a, 0, result, 1, length);
        result[0] = b;
        return result;
    }

    public static int[] prepend(final int[] a, final int b)
    {
        if (a == null)
        {
            return new int[]{ b };
        }

        final int length = a.length;
        final int[] result = new int[length + 1];
        System.arraycopy(a, 0, result, 1, length);
        result[0] = b;
        return result;
    }

    public static byte[] reverse(final byte[] a)
    {
        if (a == null)
        {
            return null;
        }

        int p1 = 0, p2 = a.length;
        final byte[] result = new byte[p2];

        while (--p2 >= 0)
        {
            result[p2] = a[p1++];
        }

        return result;
    }

    public static int[] reverse(final int[] a)
    {
        if (a == null)
        {
            return null;
        }

        int p1 = 0, p2 = a.length;
        final int[] result = new int[p2];

        while (--p2 >= 0)
        {
            result[p2] = a[p1++];
        }

        return result;
    }

    /**
     * Iterator backed by a specific array.
     */
    public static class Iterator<T>
        implements java.util.Iterator<T>
    {
        private final T[] dataArray;

        private int position = 0;

        /**
         * Base constructor.
         * <p>
         * Note: the array is not cloned, changes to it will affect the values returned by next().
         * </p>
         *
         * @param dataArray array backing the iterator.
         */
        public Iterator(final T[] dataArray)
        {
            this.dataArray = dataArray;
        }

        @Override
        public boolean hasNext()
        {
            return position < dataArray.length;
        }

        @Override
        public T next()
        {
            if (position == dataArray.length)
            {
                throw new NoSuchElementException("Out of elements: " + position);
            }

            return dataArray[position++];
        }

        @Override
        public void remove()
        {
            throw new UnsupportedOperationException("Cannot remove element from an Array.");
        }
    }
}
