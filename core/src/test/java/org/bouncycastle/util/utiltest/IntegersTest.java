package org.bouncycastle.util.utiltest;

import org.bouncycastle.util.Integers;

import junit.framework.TestCase;

public class IntegersTest
    extends TestCase
{
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
}
