package org.bouncycastle.pqc.crypto.bike;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

class BIKEUtils
{
    static void xorTo(byte[] x, byte[] z, int zLen)
    {
        for (int i = 0; i < zLen; ++i)
        {
            z[i] ^= x[i];
        }
    }

    static int getHammingWeight(byte[] bytes)
    {
        int hammingWeight = 0;
        for (int i = 0; i < bytes.length; i++)
        {
            hammingWeight += bytes[i];
        }
        return hammingWeight;
    }

    static void fromByteArrayToBitArray(byte[] out, byte[] in)
    {
        int max = (out.length / 8);
        for (int i = 0; i < max; i++)
        {
            for (int j = 0; j != 8; j++)
            {
                out[i * 8 + j] = (byte)((in[i] & (1 << j)) >>> j);
            }
        }
        if (out.length % 8 != 0)
        {
            int off = max * 8;
            int count = 0;
            while (off < out.length)
            {
                out[off++] = (byte)((in[max] & (1 << count)) >>> count);
                count++;
            }
        }
    }

    static void fromBitArrayToByteArray(byte[] out, byte[] in)
    {
        int count = 0;
        int pos = 0;
        long len = in.length;
        while (count < len)
        {
            if (count + 8 >= in.length)
            {// last set of bits cannot have enough 8 bits
                int b = in[count];
                for (int j = in.length - count - 1; j >= 1; j--)
                { //bin in reversed order
                    b |= in[count + j] << j;
                }
                out[pos] = (byte)b;
            }
            else
            {
                int b = in[count];
                for (int j = 7; j >= 1; j--)
                { //bin in reversed order
                    b |= in[count + j] << j;
                }
                out[pos] = (byte)b;
            }

            count += 8;
            pos++;
        }
    }

    static byte[] generateRandomByteArray(int mod, int size, int weight, Xof digest)
    {
        byte[] buf = new byte[4];
        int highest = Integers.highestOneBit(mod);
        int mask = highest | (highest - 1);

        byte[] res = new byte[size];
        int count = 0;
        while (count < weight)
        {
            digest.doOutput(buf, 0, 4);
            int tmp = Pack.littleEndianToInt(buf, 0) & mask;

            if (tmp < mod && setBit(res, tmp))
            {
                ++count;
            }
        }
        return res;
    }

    private static boolean setBit(byte[] a, int position)
    {
        int index = position / 8;
        int pos = position % 8;
        int selector = 1 << pos;
        boolean result = (a[index] & selector) == 0;
        a[index] |= (byte)selector;
        return result;
    }
}
