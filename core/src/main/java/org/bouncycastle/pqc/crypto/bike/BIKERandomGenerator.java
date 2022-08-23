package org.bouncycastle.pqc.crypto.bike;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.util.Pack;

class BIKERandomGenerator
{
    private static int bitScanReverse(int t)
    {
        int res = 0;
        while (t != 0)
        {
            t >>= 1;
            res++;
        }

        return res;
    }

    private static int GetRandomInMod(int mod, Xof digest)
    {
        int mask = maskNumber(bitScanReverse(mod));
        int res = -1;
        while (true)
        {
            res = getRandomNumber(digest);
            res &= mask;

            if (res < mod)
            {
                break;
            }
        }
        return res;
    }

    private static void generateRandomArray(byte[] res, int mod, int weight, Xof digest)
    {
        int index = 0;
        while (index < weight)
        {
            int tmp = GetRandomInMod(mod, digest);

            if (checkBit(res, tmp) == 0)
            { // check for new index
                setBit(res, tmp);
                index++;
            }
        }
    }

    private static int checkBit(byte[] a, int position)
    {
        int index = position / 8;
        int pos = position % 8;
        return ((a[index] >> (pos)) & 0x01);
    }


    private static void setBit(byte[] a, int position)
    {
        int index = position / 8;
        int pos = position % 8;
        a[index] |= (1 << (pos));
    }

    static byte[] generateRandomByteArray(int mod, int size, int weight, Xof digest)
    {
        byte[] res = new byte[size];
        generateRandomArray(res, mod, weight, digest);
        return res;
    }

    private static int maskNumber(int n)
    {
        return ((1 << n) - 1);
    }

    private static int getRandomNumber(Xof digest)
    {
        byte[] out = new byte[4];
        digest.doOutput(out, 0, out.length);
        int tmp = Pack.littleEndianToInt(out, 0);
        return tmp;
    }
}
