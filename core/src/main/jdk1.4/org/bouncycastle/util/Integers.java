package org.bouncycastle.util;

import org.bouncycastle.math.raw.Bits;

public class Integers
{
    private static final byte[] DEBRUIJN_TZ = {
        0x00, 0x01, 0x02, 0x18, 0x03, 0x13, 0x06, 0x19, 0x16, 0x04, 0x14, 0x0A,
        0x10, 0x07, 0x0C, 0x1A, 0x1F, 0x17, 0x12, 0x05, 0x15, 0x09, 0x0F, 0x0B,
        0x1E, 0x11, 0x08, 0x0E, 0x1D, 0x0D, 0x1C, 0x1B };

    public static int numberOfLeadingZeros(int i)
    {
        if (i <= 0)
        {
            return (~i >>> (31 - 5)) & (1 << 5);
        }

        int n = 1;
        if (0 == (i >>> 16)) { n += 16; i <<= 16; }
        if (0 == (i >>> 24)) { n +=  8; i <<=  8; }
        if (0 == (i >>> 28)) { n +=  4; i <<=  4; }
        if (0 == (i >>> 30)) { n +=  2; i <<=  2; }
        n -= (i >>> 31);
        return n;
    }

    public static int numberOfTrailingZeros(int i)
    {
        return DEBRUIJN_TZ[((i & -i) * 0x04D7651F) >>> 27];
    }

    public static int reverse(int i)
    {
        i = Bits.bitPermuteStepSimple(i, 0x55555555, 1);
        i = Bits.bitPermuteStepSimple(i, 0x33333333, 2);
        i = Bits.bitPermuteStepSimple(i, 0x0F0F0F0F, 4);
        return reverseBytes(i);
    }

    public static int reverseBytes(int i)
    {
        return rotateLeft(i & 0xFF00FF00,  8) |
               rotateLeft(i & 0x00FF00FF, 24);
    }

    public static int rotateLeft(int i, int distance)
    {
        return (i << distance) ^ (i >>> -distance);
    }

    public static int rotateRight(int i, int distance)
    {
        return (i >>> distance) ^ (i << -distance);
    }

    public static Integer valueOf(int value)
    {
        return new Integer(value);
    }
}
