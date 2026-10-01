package org.bouncycastle.util.utiltest;

import java.util.Random;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

import junit.framework.TestCase;

public class PackTest
    extends TestCase
{
    private static final byte FILL = (byte)0xA5;

    private static final long[] EXTREMES = { 0L, -1L, Long.MIN_VALUE, Long.MAX_VALUE, 0x8080808080808080L,
        0x0102030405060708L };

    /*
     * Enough calls for C2 to compile the methods under test, so that the merged stores it generates for them are
     * checked as well as the interpreter.
     */
    private static final int ITERATIONS = 200000;

    public void testLongToBigEndian()
    {
        Random random = new Random(1);
        byte[] bs = new byte[24];
        for (int i = 0; i < ITERATIONS; ++i)
        {
            long n = nextValue(random, i);
            int off = i % 9;

            Arrays.fill(bs, FILL);
            Pack.longToBigEndian(n, bs, off);
            checkBytes(n, true, bs, off);
            if (Pack.bigEndianToLong(bs, off) != n)
            {
                fail("round trip of " + Long.toHexString(n));
            }
        }

        assertTrue(Arrays.areEqual(new byte[]{ 1, 2, 3, 4, 5, 6, 7, 8 }, Pack.longToBigEndian(0x0102030405060708L)));
    }

    public void testLongToLittleEndian()
    {
        Random random = new Random(2);
        byte[] bs = new byte[24];
        for (int i = 0; i < ITERATIONS; ++i)
        {
            long n = nextValue(random, i);
            int off = i % 9;

            Arrays.fill(bs, FILL);
            Pack.longToLittleEndian(n, bs, off);
            checkBytes(n, false, bs, off);
            if (Pack.littleEndianToLong(bs, off) != n)
            {
                fail("round trip of " + Long.toHexString(n));
            }
        }

        assertTrue(Arrays.areEqual(new byte[]{ 8, 7, 6, 5, 4, 3, 2, 1 }, Pack.longToLittleEndian(0x0102030405060708L)));
    }

    public void testLongArrays()
    {
        Random random = new Random(3);
        for (int i = 0; i < 2000; ++i)
        {
            long[] ns = new long[1 + random.nextInt(25)];
            for (int j = 0; j < ns.length; ++j)
            {
                ns[j] = nextValue(random, i + j);
            }
            int nsOff = random.nextInt(ns.length);
            int nsLen = random.nextInt(ns.length - nsOff + 1);
            int bsOff = random.nextInt(9);
            int bsLen = bsOff + 8 * nsLen + random.nextInt(9);

            byte[] be = new byte[bsLen];
            Arrays.fill(be, FILL);
            Pack.longToBigEndian(ns, nsOff, nsLen, be, bsOff);
            byte[] le = new byte[bsLen];
            Arrays.fill(le, FILL);
            Pack.longToLittleEndian(ns, nsOff, nsLen, le, bsOff);
            for (int j = 0; j < nsLen; ++j)
            {
                assertEquals(ns[nsOff + j], Pack.bigEndianToLong(be, bsOff + 8 * j));
                assertEquals(ns[nsOff + j], Pack.littleEndianToLong(le, bsOff + 8 * j));
            }
            checkUntouched(be, 0, bsOff);
            checkUntouched(be, bsOff + 8 * nsLen, bsLen);
            checkUntouched(le, 0, bsOff);
            checkUntouched(le, bsOff + 8 * nsLen, bsLen);

            long[] part = Arrays.copyOfRange(ns, nsOff, nsOff + nsLen);
            assertTrue(Arrays.areEqual(Arrays.copyOfRange(be, bsOff, bsOff + 8 * nsLen), Pack.longToBigEndian(part)));
            assertTrue(Arrays.areEqual(Arrays.copyOfRange(le, bsOff, bsOff + 8 * nsLen), Pack.longToLittleEndian(part)));
        }
    }

    public void testOutOfBounds()
    {
        for (int len = 0; len < 8; ++len)
        {
            try
            {
                Pack.longToBigEndian(-1L, new byte[len], 0);
                fail("no exception for " + len + " bytes");
            }
            catch (ArrayIndexOutOfBoundsException e)
            {
                // expected
            }
            try
            {
                Pack.longToLittleEndian(-1L, new byte[len], 0);
                fail("no exception for " + len + " bytes");
            }
            catch (ArrayIndexOutOfBoundsException e)
            {
                // expected
            }
        }
    }

    /**
     * Check the 8 bytes at off against the definition of the encoding, one byte at a time, and that the bytes around
     * them are untouched.
     */
    private static void checkBytes(long n, boolean bigEndian, byte[] bs, int off)
    {
        for (int i = 0; i < 8; ++i)
        {
            int shift = bigEndian ? 56 - 8 * i : 8 * i;
            if (bs[off + i] != (byte)(n >>> shift))
            {
                fail("byte " + i + " of " + Long.toHexString(n) + (bigEndian ? " big" : " little") + " endian");
            }
        }
        checkUntouched(bs, 0, off);
        checkUntouched(bs, off + 8, bs.length);
    }

    private static void checkUntouched(byte[] bs, int from, int to)
    {
        for (int i = from; i < to; ++i)
        {
            if (bs[i] != FILL)
            {
                fail("byte " + i + " overwritten");
            }
        }
    }

    /**
     * Random values, values with a single byte set or clear at each position in turn, and extremes.
     */
    private static long nextValue(Random random, int i)
    {
        long oneByte = (long)(1 + random.nextInt(255)) << (8 * ((i >> 2) & 7));
        switch (i & 3)
        {
        case 0:
            return random.nextLong();
        case 1:
            return oneByte;
        case 2:
            return ~oneByte;
        default:
            return EXTREMES[(i >> 2) % EXTREMES.length];
        }
    }
}
