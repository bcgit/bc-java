package org.bouncycastle.util.utiltest;

import java.util.Random;

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
}
