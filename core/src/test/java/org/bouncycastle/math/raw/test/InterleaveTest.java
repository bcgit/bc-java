package org.bouncycastle.math.raw.test;

import java.security.SecureRandom;

import org.bouncycastle.math.raw.Interleave;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class InterleaveTest extends TestCase
{
    private static final int ITERATIONS = 1000;

    private static final SecureRandom R = new SecureRandom();

    public void testExpand8To16()
    {
        // NOTE: Just test all inputs here
        for (int iteration = 0; iteration < 256; ++iteration)
        {
            // NOTE: Implementation is expected to mask input
            int x = iteration | (R.nextInt() << 8);
            int expected = (int)referenceShuffle(x & 0xFFL);
            int actual = Interleave.expand8to16(x);
            assertEquals(expected, actual);
        }
    }

    public void testExpand16To32()
    {
        for (int iteration = 0; iteration < ITERATIONS; ++iteration)
        {
            // NOTE: Implementation is expected to mask input
            int x = R.nextInt();
            int expected = (int)referenceShuffle(x & 0xFFFFL);
            int actual = Interleave.expand16to32(x);
            assertEquals(expected, actual);
        }
    }

    public void testExpand32To64()
    {
        for (int iteration = 0; iteration < ITERATIONS; ++iteration)
        {
            int x = R.nextInt();
            long expected = referenceShuffle(x & 0xFFFFFFFFL);
            long actual = Interleave.expand32to64(x);
            assertEquals(expected, actual);
        }
    }

    public void testExpand64To128()
    {
        for (int iteration = 0; iteration < ITERATIONS; ++iteration)
        {
            long x = R.nextLong();
            long expected = referenceShuffle(x);
            long[] actual = new long[9];
            int offset = iteration % 8;
            // NOTE: Implementation must overwrite existing values
            actual[offset    ] = R.nextLong();
            actual[offset + 1] = R.nextLong();
            Interleave.expand64To128(x, actual, offset);
            assertEquals((expected      ) & 0x5555555555555555L, actual[offset    ]);
            assertEquals((expected >>> 1) & 0x5555555555555555L, actual[offset + 1]);
        }
    }

    public static Test suite()
    {
        return new TestSuite(InterleaveTest.class);
    }

    private static long referenceShuffle(long x)
    {
        long result = 0, y = x >>> 32;
        for (int bit = 0; bit < 32; ++bit)
        {
            long selector = 1L << bit;
            result |= ((x & selector) << (bit    ));
            result |= ((y & selector) << (bit + 1));
        }
        return result;
    }
}
