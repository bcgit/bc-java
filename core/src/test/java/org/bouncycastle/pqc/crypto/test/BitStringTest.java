package org.bouncycastle.pqc.crypto.test;

import junit.framework.TestCase;
import org.bouncycastle.pqc.crypto.ntru.IndexGenerator.BitString;
import org.bouncycastle.util.Arrays;

public class BitStringTest
    extends TestCase
{
    public void testAppendBitsByteArray()
    {
        BitString bs = new BitString();
        bs.appendBits((byte)78);
        assertBitStringEquals(bs, new byte[]{78});
        bs.appendBits((byte)-5);
        assertBitStringEquals(bs, new byte[]{78, -5});
        bs.appendBits((byte)127);
        assertBitStringEquals(bs, new byte[]{78, -5, 127});
        bs.appendBits((byte)0);
        assertBitStringEquals(bs, new byte[]{78, -5, 127, 0});
        bs.appendBits((byte)100);
        assertBitStringEquals(bs, new byte[]{78, -5, 127, 0, 100});
    }

    private void assertBitStringEquals(BitString bs, byte[] arr)
    {
        byte[] bsBytes = bs.getBytes();

        assertTrue(bsBytes.length >= arr.length);
        arr = copyOf(arr, bsBytes.length);
        assertTrue(Arrays.areEqual(arr, bsBytes));
    }

    public void testGetTrailing()
    {
        BitString bs = new BitString();
        bs.appendBits((byte)78);
        BitString bs2 = bs.getTrailing(3);
        assertBitStringEquals(bs2, new byte[]{6});

        bs = new BitString();
        bs.appendBits((byte)78);
        bs.appendBits((byte)-5);
        bs2 = bs.getTrailing(9);
        assertBitStringEquals(bs2, new byte[]{78, 1});

        bs2.appendBits((byte)100);
        assertBitStringEquals(bs2, new byte[]{78, -55});
        bs = bs2.getTrailing(13);
        assertBitStringEquals(bs, new byte[]{78, 9});
        bs2 = bs2.getTrailing(11);
        assertBitStringEquals(bs2, new byte[]{78, 1});

        bs2.appendBits((byte)100);
        assertBitStringEquals(bs2, new byte[]{78, 33, 3});
        bs2 = bs2.getTrailing(16);
        assertBitStringEquals(bs2, new byte[]{78, 33});
    }

    public void testGetLeadingAsInt()
    {
        BitString bs = new BitString();
        bs.appendBits((byte)78);
        bs.appendBits((byte)42);
        assertEquals(1, bs.getLeadingAsInt(3));
        assertEquals(84, bs.getLeadingAsInt(9));
        assertEquals(338, bs.getLeadingAsInt(11));

        BitString bs2 = bs.getTrailing(11);
        assertBitStringEquals(bs2, new byte[]{78, 2});
        assertEquals(590, bs2.getLeadingAsInt(11));
        assertEquals(9, bs2.getLeadingAsInt(5));

        bs2.appendBits((byte)115);
        assertEquals(230, bs2.getLeadingAsInt(9));
        assertEquals(922, bs2.getLeadingAsInt(11));

        bs2.appendBits((byte)-36);
        assertEquals(55, bs2.getLeadingAsInt(6));
    }

    private byte[] copyOf(byte[] src, int length)
    {
        byte[] tmp = new byte[length];
        System.arraycopy(src, 0, tmp, 0, tmp.length > src.length ? src.length : tmp.length);
        return tmp;
    }
}
