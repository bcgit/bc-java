package org.bouncycastle.pqc.crypto.bike;

import org.bouncycastle.util.Arrays;

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
        byte[] tmpByte = Arrays.clone(in);
        String res = "";
        for (int i = 0; i < tmpByte.length; i++)
        {
            boolean negative = false;
            String tmp = "";
            tmp += Integer.toBinaryString(tmpByte[i] & 0xff);
            tmp = new StringBuilder(tmp).reverse().toString();
            if (tmpByte[i] != 0)
            {
                int t = tmpByte[i];
            }
            // padding with zeros
            int gap = 0;
            if (i == tmpByte.length - 1 && tmpByte.length % 8 != 0)
            {
                gap = out.length % 8 - tmp.length(); // last byte so it cannot parse to 8 bits
            }
            else
            {
                gap = 8 - tmp.length();
            }
            while (gap > 0)
            {
                tmp = tmp + '0';
                gap--;
            }
            res += tmp;
        }
        fromBitStringToBytes(out, res);
    }

    static void fromBitStringToBytes(byte[] out, String in)
    {
        for (int i = 0; i < out.length; i++)
        {
            out[i] = (byte)(in.charAt(i) - '0');
        }
    }

    static void fromBitArrayToByteArray(byte[] out, byte[] in)
    {
        int count = 0;
        int pos = 0;
        byte[] tmpIn = Arrays.clone(in);
        long len = tmpIn.length;
        while (count < len)
        {
            String tmp = "";

            if (count + 8 >= tmpIn.length)
            {// last set of bits cannot have enough 8 bits
                for (int j = tmpIn.length - count - 1; j >= 0; j--)
                { //bin in reversed order
                    tmp += tmpIn[count + j];
                }
            }

            else
            {
                for (int j = 7; j >= 0; j--)
                { //bin in reversed order
                    tmp += tmpIn[count + j];
                }
            }

            int b = Integer.parseInt(tmp, 2);
            out[pos] = (byte)b;
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
