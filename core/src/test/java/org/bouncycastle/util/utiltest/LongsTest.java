package org.bouncycastle.util.utiltest;

import java.math.BigInteger;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Longs;
import org.bouncycastle.util.Pack;

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

    public void testToUnsignedByteArray()
    {
        assertEquals(0, Longs.toUnsignedByteArray(0L).length);
        assertTrue(Arrays.areEqual(new byte[]{ 1 }, Longs.toUnsignedByteArray(1L)));
        assertTrue(Arrays.areEqual(new byte[]{ (byte)0xFF }, Longs.toUnsignedByteArray(255L)));
        assertTrue(Arrays.areEqual(new byte[]{ 1, 0 }, Longs.toUnsignedByteArray(256L)));

        // every octet-count boundary, against the BigInteger form
        for (int bits = 1; bits < 64; ++bits)
        {
            long atBoundary = 1L << bits;
            checkAgainstBigInteger(atBoundary - 1);
            checkAgainstBigInteger(atBoundary);
            checkAgainstBigInteger(atBoundary + 1);
        }
        checkAgainstBigInteger(Long.MAX_VALUE);

        // a negative argument is the unsigned 64-bit value, so all eight octets
        for (int bits = 0; bits < 64; ++bits)
        {
            long negative = Long.MIN_VALUE >>> bits | Long.MIN_VALUE;
            assertTrue(Arrays.areEqual(Pack.longToBigEndian(negative), Longs.toUnsignedByteArray(negative)));
        }
        assertTrue(Arrays.areEqual(Pack.longToBigEndian(-1L), Longs.toUnsignedByteArray(-1L)));
    }

    private static void checkAgainstBigInteger(long i)
    {
        byte[] expected = BigIntegers.asUnsignedByteArray(BigInteger.valueOf(i));
        assertTrue(Long.toString(i), Arrays.areEqual(expected, Longs.toUnsignedByteArray(i)));
    }
}
