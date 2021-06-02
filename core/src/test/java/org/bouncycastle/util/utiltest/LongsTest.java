package org.bouncycastle.util.utiltest;

import org.bouncycastle.util.Longs;

import junit.framework.TestCase;

public class LongsTest
    extends TestCase
{
    public void testNumberOfLeadingZeros()
    {
        for (int i = 0; i < 63; ++i)
        {
            assertEquals(i, Longs.numberOfLeadingZeros(Long.MIN_VALUE >>> i));
            assertEquals(i, Longs.numberOfLeadingZeros(-1L >>> i));
        }

        assertEquals(63, Longs.numberOfLeadingZeros(1L));
        assertEquals(64, Longs.numberOfLeadingZeros(0L));
    }

    public void testNumberOfTrailingZeros()
    {
        for (int i = 0; i < 63; ++i)
        {
            assertEquals(i, Longs.numberOfTrailingZeros(1L << i));
            assertEquals(i, Longs.numberOfTrailingZeros(-1L << i));
        }

        assertEquals(63, Longs.numberOfTrailingZeros(Long.MIN_VALUE));
        assertEquals(64, Longs.numberOfTrailingZeros(0L));
    }
}
