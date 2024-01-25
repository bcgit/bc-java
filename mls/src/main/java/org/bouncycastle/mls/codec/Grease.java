package org.bouncycastle.mls.codec;

import java.util.Random;

public class Grease
{
    static short[] grease = new short[]{0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        (short)0x8A8A, (short)0x9A9A, (short)0xAAAA, (short)0xBABA, (short)0xCACA, (short)0xDADA, (short)0xEAEA};

    public static short getGrease()
    {
        Random random = new Random();
        return grease[random.nextInt(15)];
    }

    public static short isGrease(short type)
    {
        switch (type)
        {
        case 0x0A0A:
            return 0;
        case 0x1A1A:
            return 1;
        case 0x2A2A:
            return 2;
        case 0x3A3A:
            return 3;
        case 0x4A4A:
            return 4;
        case 0x5A5A:
            return 5;
        case 0x6A6A:
            return 6;
        case 0x7A7A:
            return 7;
        case (short)0x8A8A:
            return 8;
        case (short)0x9A9A:
            return 9;
        case (short)0xAAAA:
            return 10;
        case (short)0xBABA:
            return 11;
        case (short)0xCACA:
            return 12;
        case (short)0xDADA:
            return 13;
        case (short)0xEAEA:
            return 14;
        default:
            return -1;
        }

    }
}
