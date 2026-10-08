package org.bouncycastle.util.utiltest;

import java.util.Random;

import java.math.BigInteger;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Integers;

import junit.framework.TestCase;

public class IntegersTest
    extends TestCase
{
    public void testBitCount()
    {
    	Random random = new Random();

    	for (int pos = 0; pos <= 24; ++pos)
    	{
    		int seed = random.nextInt();
    		implTestBitCountRange(seed, pos, 256);
    	}
    }

    public void testNumberOfLeadingZeros()
    {
        for (int i = 0; i < 31; ++i)
        {
            assertEquals(i, Integers.numberOfLeadingZeros(Integer.MIN_VALUE >>> i));
            assertEquals(i, Integers.numberOfLeadingZeros(-1 >>> i));
        }

        assertEquals(31, Integers.numberOfLeadingZeros(1));
        assertEquals(32, Integers.numberOfLeadingZeros(0));
    }

    public void testNumberOfTrailingZeros()
    {
        for (int i = 0; i < 31; ++i)
        {
            assertEquals(i, Integers.numberOfTrailingZeros(1 << i));
            assertEquals(i, Integers.numberOfTrailingZeros(-1 << i));
        }

        assertEquals(31, Integers.numberOfTrailingZeros(Integer.MIN_VALUE));
        assertEquals(32, Integers.numberOfTrailingZeros(0));
    }

    private static void implTestBitCountRange(int seed, int pos, int count)
    {
    	for (int i = 0; i < count; ++i)
    	{
    		int n = seed + (i << pos);
            assertEquals(simpleBitCount(n), Integers.bitCount(n));
    	}
    }

    private static int simpleBitCount(int n)
    {
    	int count = 0;
    	for (int i = 0; i < 32; ++i)
    	{
    		count += (n >>> i) & 1;
    	}
    	return count;
    }

    public void testToUnsignedByteArray()
    {
        assertEquals(0, Integers.toUnsignedByteArray(0).length);
        assertTrue(Arrays.areEqual(new byte[]{ 1 }, Integers.toUnsignedByteArray(1)));
        assertTrue(Arrays.areEqual(new byte[]{ (byte)0xFF }, Integers.toUnsignedByteArray(255)));
        assertTrue(Arrays.areEqual(new byte[]{ 1, 0 }, Integers.toUnsignedByteArray(256)));

        // every octet-count boundary, against the BigInteger form
        for (int bits = 1; bits < 32; ++bits)
        {
            int atBoundary = 1 << bits;
            checkAgainstBigInteger(atBoundary - 1);
            checkAgainstBigInteger(atBoundary);
            checkAgainstBigInteger(atBoundary + 1);
        }
        checkAgainstBigInteger(Integer.MAX_VALUE);

        // a negative argument is the unsigned 32-bit value, so all four octets
        for (int bits = 0; bits < 32; ++bits)
        {
            int negative = Integer.MIN_VALUE >>> bits | Integer.MIN_VALUE;
            assertTrue(Arrays.areEqual(Pack.intToBigEndian(negative), Integers.toUnsignedByteArray(negative)));
        }
        assertTrue(Arrays.areEqual(Pack.intToBigEndian(-1), Integers.toUnsignedByteArray(-1)));
    }

    private static void checkAgainstBigInteger(int i)
    {
        byte[] expected = BigIntegers.asUnsignedByteArray(BigInteger.valueOf(i));
        assertTrue(Integer.toString(i), Arrays.areEqual(expected, Integers.toUnsignedByteArray(i)));
    }
}
