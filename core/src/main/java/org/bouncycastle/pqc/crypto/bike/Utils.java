package org.bouncycastle.pqc.crypto.bike;

class Utils
{
    static byte[] xorBytes(byte[] a, byte[] b, int size)
    {
        byte[] out = new byte[size];

        for (int i = 0; i < size; i++)
        {
            out[i] = (byte)(a[i] ^ b[i]);
        }
        return out;
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

    static byte[] removeLast0Bits(byte[] out)
    {
        int lastIndexOf1 = 0;
        for (int i = out.length - 1; i >= 0; i--)
        {
            if (out[i] == 1)
            {
                lastIndexOf1 = i;
                break;
            }
        }
        byte[] res = new byte[lastIndexOf1 + 1];
        System.arraycopy(out, 0, res, 0, res.length);
        return res;
    }

    static byte[] append0s(byte[] in, int length)
    {
        byte[] out = new byte[length];
        System.arraycopy(in, 0, out, 0, in.length);
        return out;
    }
}
