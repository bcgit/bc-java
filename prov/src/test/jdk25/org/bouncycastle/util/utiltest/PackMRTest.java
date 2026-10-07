package org.bouncycastle.util.utiltest;

import java.net.URL;
import java.util.Random;

import junit.framework.TestCase;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Pack has a META-INF/versions/23 copy whose longToLittleEndian writes the bytes of the long directly. Check a JDK 25
 * runtime loads that copy from the multi-release jar, and that both byte orders are right once C2 has compiled them.
 */
public class PackMRTest
    extends TestCase
{
    private static final byte FILL = (byte)0xA5;

    private static final int ITERATIONS = 200000;

    public void testVersionedCopyLoaded()
    {
        URL url = Pack.class.getResource("Pack.class");

        assertNotNull(url);
        assertTrue(url.toString(), url.toString().endsWith("!/META-INF/versions/23/org/bouncycastle/util/Pack.class"));
    }

    public void testLongToLittleEndian()
    {
        Random random = new Random(1);
        byte[] bs = new byte[24];
        for (int i = 0; i < ITERATIONS; ++i)
        {
            long n = (i & 1) == 0 ? random.nextLong() : 0xFFL << (8 * (i % 8));
            int off = i % 9;

            Arrays.fill(bs, FILL);
            Pack.longToLittleEndian(n, bs, off);
            checkBytes(n, false, bs, off);
            assertEquals(n, Pack.littleEndianToLong(bs, off));
        }
    }

    public void testLongToBigEndian()
    {
        Random random = new Random(2);
        byte[] bs = new byte[24];
        for (int i = 0; i < ITERATIONS; ++i)
        {
            long n = (i & 1) == 0 ? random.nextLong() : 0xFFL << (8 * (i % 8));
            int off = i % 9;

            Arrays.fill(bs, FILL);
            Pack.longToBigEndian(n, bs, off);
            checkBytes(n, true, bs, off);
            assertEquals(n, Pack.bigEndianToLong(bs, off));
        }
    }

    public void testLongArrays()
    {
        long[] ns = new long[21];
        for (int i = 0; i < ns.length; ++i)
        {
            ns[i] = 0x0102030405060708L * (i + 1);
        }
        byte[] le = Pack.longToLittleEndian(ns);
        byte[] be = Pack.longToBigEndian(ns);
        for (int i = 0; i < ns.length; ++i)
        {
            assertEquals(ns[i], Pack.littleEndianToLong(le, 8 * i));
            assertEquals(ns[i], Pack.bigEndianToLong(be, 8 * i));
        }
    }

    private static void checkBytes(long n, boolean bigEndian, byte[] bs, int off)
    {
        for (int i = 0; i < 8; ++i)
        {
            int shift = bigEndian ? 56 - 8 * i : 8 * i;
            assertEquals("byte " + i + " of " + Long.toHexString(n), (byte)(n >>> shift), bs[off + i]);
        }
        for (int i = 0; i < bs.length; ++i)
        {
            if (i < off || i >= off + 8)
            {
                assertEquals("byte " + i + " overwritten", FILL, bs[i]);
            }
        }
    }
}
