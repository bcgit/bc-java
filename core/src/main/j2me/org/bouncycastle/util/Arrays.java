package org.bouncycastle.util;

import java.math.BigInteger;
import java.util.Iterator;

/**
 * General array utilities.
 */
public final class Arrays
{
    private Arrays()
    {
        // static class, hide constructor
    }

    public static boolean areAllZeroes(byte[] buf, int off, int len)
    {
        int bits = 0;
        for (int i = 0; i < len; ++i)
        {
            bits |= buf[off + i];
        }
        return bits == 0;
    }
    
    public static boolean areEqual(
        boolean[] a,
        boolean[] b)
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
        char[] a,
        char[] b)
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
        byte[] a,
        byte[] b)
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

    public static boolean areEqual(byte[] a, int aFromIndex, int aToIndex, byte[] b, int bFromIndex, int bToIndex)
    {
        int aLength = aToIndex - aFromIndex;
        int bLength = bToIndex - bFromIndex;

        if (aLength != bLength)
        {
            return false;
        }

        for (int i = 0; i < aLength; ++i)
        {
            if (a[aFromIndex + i] != b[bFromIndex + i])
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
        byte[] a,
        byte[] b)
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
        int[] a,
        int[] b)
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
        long[] a,
        long[] b)
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

    public static boolean areEqual(Object[] a, Object[] b)
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
            Object objA = a[i], objB = b[i];
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

    public static boolean contains(short[] a, short n)
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

    public static boolean contains(int[] a, int n)
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
        byte[] array,
        int start,
        int finish,
        byte value)
    {
        for (int i = start; i < finish; i++)
        {
            array[i] = value;
        }
    }
    
    public static void fill(
        byte[] array,
        byte value)
    {
        for (int i = 0; i < array.length; i++)
        {
            array[i] = value;
        }
    }

    public static void fill(
        char[] array,
        char value)
    {
        for (int i = 0; i < array.length; i++)
        {
            array[i] = value;
        }
    }

    public static void fill(
        long[] array,
        long value)
    {
        for (int i = 0; i < array.length; i++)
        {
            array[i] = value;
        }
    }

    public static void fill(
        short[] array,
        short value)
    {
        for (int i = 0; i < array.length; i++)
        {
            array[i] = value;
        }
    }

    public static void fill(
        int[] array,
        int value)
    {
        for (int i = 0; i < array.length; i++)
        {
            array[i] = value;
        }
    }

    public static int hashCode(byte[] data)
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

    public static int hashCode(byte[] data, int off, int len)
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

    public static int hashCode(char[] data)
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

    public static int hashCode(int[][] ints)
    {
        int hc = 0;

        for (int i = 0; i != ints.length; i++)
        {
            hc = hc * 257 + hashCode(ints[i]);
        }

        return hc;
    }

    public static int hashCode(int[] data)
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

    public static int hashCode(int[] data, int off, int len)
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

    public static int hashCode(long[] data)
    {
        if (data == null)
        {
            return 0;
        }

        int i = data.length;
        int hc = i + 1;

        while (--i >= 0)
        {
            long di = data[i];
            hc *= 257;
            hc ^= (int)di;
            hc *= 257;
            hc ^= (int)(di >>> 32);
        }

        return hc;
    }

    public static int hashCode(long[] data, int off, int len)
    {
        if (data == null)
        {
            return 0;
        }

        int i = len;
        int hc = i + 1;

        while (--i >= 0)
        {
            long di = data[off + i];
            hc *= 257;
            hc ^= (int)di;
            hc *= 257;
            hc ^= (int)(di >>> 32);
        }

        return hc;
    }

    public static int hashCode(short[][][] shorts)
    {
        int hc = 0;

        for (int i = 0; i != shorts.length; i++)
        {
            hc = hc * 257 + hashCode(shorts[i]);
        }

        return hc;
    }

    public static int hashCode(short[][] shorts)
    {
        int hc = 0;

        for (int i = 0; i != shorts.length; i++)
        {
            hc = hc * 257 + hashCode(shorts[i]);
        }

        return hc;
    }

    public static int hashCode(short[] data)
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

    public static int hashCode(Object[] data)
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

    public static byte[] clone(byte[] data)
    {
        if (data == null)
        {
            return null;
        }
        byte[] copy = new byte[data.length];

        System.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    public static char[] clone(char[] data)
    {
        if (data == null)
        {
            return null;
        }
        char[] copy = new char[data.length];

        System.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    public static byte[] clone(byte[] data, byte[] existing)
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

    public static byte[][] clone(byte[][] data)
    {
        if (data == null)
        {
            return null;
        }

        byte[][] copy = new byte[data.length][];

        for (int i = 0; i != copy.length; i++)
        {
            copy[i] = clone(data[i]);
        }

        return copy;
    }

    public static byte[][][] clone(byte[][][] data)
    {
        if (data == null)
        {
            return null;
        }

        byte[][][] copy = new byte[data.length][][];

        for (int i = 0; i != copy.length; i++)
        {
            copy[i] = clone(data[i]);
        }

        return copy;
    }

    public static int[] clone(int[] data)
    {
        if (data == null)
        {
            return null;
        }
        int[] copy = new int[data.length];

        System.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    public static long[] clone(long[] data)
    {
        if (data == null)
        {
            return null;
        }
        long[] copy = new long[data.length];

        System.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    public static long[] clone(long[] data, long[] existing)
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

    public static short[] clone(short[] data)
    {
        if (data == null)
        {
            return null;
        }
        short[] copy = new short[data.length];

        System.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    public static BigInteger[] clone(BigInteger[] data)
    {
        if (data == null)
        {
            return null;
        }
        BigInteger[] copy = new BigInteger[data.length];

        System.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    public static byte[] copyOf(byte[] data, int newLength)
    {
        byte[] tmp = new byte[newLength];

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

    public static char[] copyOf(char[] data, int newLength)
    {
        char[] tmp = new char[newLength];

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

    public static int[] copyOf(int[] data, int newLength)
    {
        int[] tmp = new int[newLength];

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

    public static long[] copyOf(long[] data, int newLength)
    {
        long[] tmp = new long[newLength];

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

    public static BigInteger[] copyOf(BigInteger[] data, int newLength)
    {
        BigInteger[] tmp = new BigInteger[newLength];

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
     * @param to   the final index of the range (exclusive).
     * @return a new byte array containing the range given.
     */
    public static byte[] copyOfRange(byte[] data, int from, int to)
    {
        int newLength = getLength(from, to);

        byte[] tmp = new byte[newLength];

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

    public static int[] copyOfRange(int[] data, int from, int to)
    {
        int newLength = getLength(from, to);

        int[] tmp = new int[newLength];

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

    public static long[] copyOfRange(long[] data, int from, int to)
    {
        int newLength = getLength(from, to);

        long[] tmp = new long[newLength];

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

    public static BigInteger[] copyOfRange(BigInteger[] data, int from, int to)
    {
        int newLength = getLength(from, to);

        BigInteger[] tmp = new BigInteger[newLength];

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

    private static int getLength(int from, int to)
    {
        int newLength = to - from;
        if (newLength < 0)
        {
            StringBuffer sb = new StringBuffer(from);
            sb.append(" > ").append(to);
            throw new IllegalArgumentException(sb.toString());
        }
        return newLength;
    }

    public static byte[] append(byte[] a, byte b)
    {
        if (a == null)
        {
            return new byte[]{b};
        }

        int length = a.length;
        byte[] result = new byte[length + 1];
        System.arraycopy(a, 0, result, 0, length);
        result[length] = b;
        return result;
    }

    public static short[] append(short[] a, short b)
    {
        if (a == null)
        {
            return new short[]{b};
        }

        int length = a.length;
        short[] result = new short[length + 1];
        System.arraycopy(a, 0, result, 0, length);
        result[length] = b;
        return result;
    }

    public static int[] append(int[] a, int b)
    {
        if (a == null)
        {
            return new int[]{b};
        }

        int length = a.length;
        int[] result = new int[length + 1];
        System.arraycopy(a, 0, result, 0, length);
        result[length] = b;
        return result;
    }

    public static byte[] concatenate(byte[] a, byte[] b)
    {
        if (a != null && b != null)
        {
            byte[] rv = new byte[a.length + b.length];

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

    public static byte[] concatenate(byte[] a, byte[] b, byte[] c)
    {
        if (a != null && b != null && c != null)
        {
            byte[] rv = new byte[a.length + b.length + c.length];

            System.arraycopy(a, 0, rv, 0, a.length);
            System.arraycopy(b, 0, rv, a.length, b.length);
            System.arraycopy(c, 0, rv, a.length + b.length, c.length);

            return rv;
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

    public static byte[] concatenate(byte[] a, byte[] b, byte[] c, byte[] d)
    {
        if (a != null && b != null && c != null && d != null)
        {
            byte[] rv = new byte[a.length + b.length + c.length + d.length];

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

    public static int[] concatenate(int[] a, int[] b)
    {
        if (a == null)
        {
            return clone(b);
        }
        if (b == null)
        {
            return clone(a);
        }

        int[] c = new int[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    public static byte[] prepend(byte[] a, byte b)
    {
        if (a == null)
        {
            return new byte[]{b};
        }

        int length = a.length;
        byte[] result = new byte[length + 1];
        System.arraycopy(a, 0, result, 1, length);
        result[0] = b;
        return result;
    }

    public static short[] prepend(short[] a, short b)
    {
        if (a == null)
        {
            return new short[]{b};
        }

        int length = a.length;
        short[] result = new short[length + 1];
        System.arraycopy(a, 0, result, 1, length);
        result[0] = b;
        return result;
    }

    public static int[] prepend(int[] a, int b)
    {
        if (a == null)
        {
            return new int[]{b};
        }

        int length = a.length;
        int[] result = new int[length + 1];
        System.arraycopy(a, 0, result, 1, length);
        result[0] = b;
        return result;
    }

    public static byte[] reverse(byte[] a)
    {
        if (a == null)
        {
            return null;
        }

        int p1 = 0, p2 = a.length;
        byte[] result = new byte[p2];

        while (--p2 >= 0)
        {
            result[p2] = a[p1++];
        }

        return result;
    }

    public static int[] reverse(int[] a)
    {
        if (a == null)
        {
            return null;
        }

        int p1 = 0, p2 = a.length;
        int[] result = new int[p2];

        while (--p2 >= 0)
        {
            result[p2] = a[p1++];
        }

        return result;
    }

    public static byte[] concatenate(byte[][] arrays)
    {
        int size = 0;
        for (int i = 0; i != arrays.length; i++)
        {
            size += arrays[i].length;
        }

        byte[] rv = new byte[size];

        int offSet = 0;
        for (int i = 0; i != arrays.length; i++)
        {
            System.arraycopy(arrays[i], 0, rv, offSet, arrays[i].length);
            offSet += arrays[i].length;
        }

        return rv;
    }

    /**
     * Fill input array by zeros
     *
     * @param array input array
     */
    public static void clear(byte[] array)
    {
        if (array != null)
        {
            for (int i = 0; i < array.length; i++)
            {
                array[i] = 0;
            }
        }
    }

    public static void clear(int[] array)
    {
        if (array != null)
        {
            for (int i = 0; i < array.length; i++)
            {
                array[i] = 0;
            }
        }
    }

    public static boolean isNullOrContainsNull(Object[] array)
    {
        if (null == array)
        {
            return true;
        }
        int count = array.length;
        for (int i = 0; i < count; ++i)
        {
            if (null == array[i])
            {
                return true;
            }
        }
        return false;
    }

    public static boolean constantTimeAreEqual(int len, byte[] a, int aOff, byte[] b, int bOff)
    {
        if (null == a)
        {
            throw new NullPointerException("'a' cannot be null");
        }
        if (null == b)
        {
            throw new NullPointerException("'b' cannot be null");
        }
        if (len < 0)
        {
            throw new IllegalArgumentException("'len' cannot be negative");
        }
        if (aOff > (a.length - len))
        {
            throw new IndexOutOfBoundsException("'aOff' value invalid for specified length");
        }
        if (bOff > (b.length - len))
        {
            throw new IndexOutOfBoundsException("'bOff' value invalid for specified length");
        }

        int d = 0;
        for (int i = 0; i < len; ++i)
        {
            d |= (a[aOff + i] ^ b[bOff + i]);
        }
        return 0 == d;
    }

    /**
     * Iterator backed by a specific array.
     */
    public static class Iterator
        implements java.util.Iterator
    {
        private final Object[] dataArray;

        private int position = 0;

        /**
         * Base constructor.
         * <p>
         * Note: the array is not cloned, changes to it will affect the values returned by next().
         * </p>
         *
         * @param dataArray array backing the iterator.
         */
        public Iterator(Object[] dataArray)
        {
            this.dataArray = dataArray;
        }

        public boolean hasNext()
        {
            return position < dataArray.length;
        }

        public Object next()
        {
            return dataArray[position++];
        }

        public void remove()
        {
            throw new RuntimeException("Cannot remove element from an Array.");
        }
    }
}
