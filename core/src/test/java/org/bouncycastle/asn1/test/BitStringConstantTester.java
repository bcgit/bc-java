package org.bouncycastle.asn1.test;

public class BitStringConstantTester
{
    private static final int[] bits =
    { 
        1 << 7, 1 << 6, 1 << 5, 1 << 4, 1 << 3, 1 << 2, 1 << 1, 1 << 0,
        1 << 15, 1 << 14, 1 << 13, 1 << 12, 1 << 11, 1 << 10, 1 << 9, 1 << 8,
        1 << 23, 1 << 22, 1 << 21, 1 << 20, 1 << 19, 1 << 18, 1 << 17, 1 << 16,
        1 << 31, 1 << 30, 1 << 29, 1 << 28, 1 << 27, 1 << 26, 1 << 25, 1 << 24
    };
    
    public static void testFlagValueCorrect(
        int bitNo,
        int value)
    {
        if (bits[bitNo] != value)
        {
            throw new IllegalArgumentException("bit value " + bitNo + " wrong");
        }
    }
}
