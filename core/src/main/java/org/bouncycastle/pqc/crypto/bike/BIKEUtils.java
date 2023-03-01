package org.bouncycastle.pqc.crypto.bike;

import org.bouncycastle.crypto.Xof;
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

    static void fromBitArrayToByteArray(byte[] out, byte[] in, int inOff, int inLen)
    {
        int count = 0;
        int pos = 0;
        long len = inLen;
        while (count < len)
        {
            if (count + 8 >= inLen)
            {// last set of bits cannot have enough 8 bits
                int b = in[inOff + count];
                for (int j = inLen - count - 1; j >= 1; j--)
                { //bin in reversed order
                    b |= in[inOff + count + j] << j;
                }
                out[pos] = (byte)b;
            }
            else
            {
                int b = in[inOff + count];
                for (int j = 7; j >= 1; j--)
                { //bin in reversed order
                    b |= in[inOff + count + j] << j;
                }
                out[pos] = (byte)b;
            }

            count += 8;
            pos++;
        }
    }

    static void generateRandomByteArray(byte[] res, int size, int weight, Xof digest)
    {
        byte[] buf = new byte[4];
        int rand_pos;

        for (int i = weight - 1; i >= 0; i--)
        {
            digest.doOutput(buf, 0, 4);
            long temp = ((long)Pack.littleEndianToInt(buf, 0)) & 0xFFFFFFFFL;
            temp = temp * (size - i) >> 32;
            rand_pos = (int) temp;

            rand_pos += i;

            if(CHECK_BIT(res, rand_pos) != 0)
            {
                rand_pos = i;
            }
            SET_BIT(res, rand_pos);
        }
    }
    protected static int CHECK_BIT(byte[] tmp, int position)
    {
        int index = position / 8;
        int pos = position % 8;
        return ((tmp[index] >>> (pos))  & 0x01);
    }
    protected static void SET_BIT(byte[] tmp, int position)
    {
        int index = position/8;
        int pos = position%8;
        tmp[index] |= (long)(1L << (long)(pos));
    }
}
