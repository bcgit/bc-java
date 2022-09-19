package org.bouncycastle.pqc.crypto.hqc;

import java.math.BigInteger;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class Utils
{

    static void fromBitStringToBytes(byte[] out, String in)
    {
        for (int i = 0; i < out.length; i++)
        {
            out[i] = (byte)(in.charAt(i) - '0');
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

    static void fromBitArrayToUnsignedIntArray(int[] out, byte[] in)
    {
        int count = 0;
        int pos = 0;
        byte[] tmpIn = Arrays.clone(in);
        long len = tmpIn.length;
        while (count < len)
        {
            String tmp = "";

            if (count + 16 >= tmpIn.length)
            {// last set of bits cannot have enough 8 bits
                for (int j = tmpIn.length - count - 1; j >= 0; j--)
                { //bin in reversed order
                    tmp += tmpIn[count + j];
                }
            }

            else
            {
                for (int j = 15; j >= 0; j--)
                { //bin in reversed order
                    tmp += tmpIn[count + j];
                }
            }

            int b = Integer.parseInt(tmp, 2);
            out[pos] = b;
            count += 16;
            pos++;
        }
    }

    static void fromBitArrayToLongArray(long[] out, byte[] in)
    {
        int count = 0;
        int pos = 0;
        byte[] tmpIn = Arrays.clone(in);
        long len = tmpIn.length;
        while (count < len)
        {
            String tmp = "";

            if (count + 64 >= tmpIn.length)
            {// last set of bits cannot have enough 8 bits
                for (int j = tmpIn.length - count - 1; j >= 0; j--)
                { //bin in reversed order
                    tmp += tmpIn[count + j];
                }
            }

            else
            {
                for (int j = 63; j >= 0; j--)
                { //bin in reversed order
                    tmp += tmpIn[count + j];
                }
            }

            BigInteger a = new BigInteger(tmp, 2);
            long b = a.longValue();
            out[pos] = b;
            count += 64;
            pos++;
        }
    }

    static void fromBitArrayToByte32Array(int[] out, byte[] in)
    {
        int count = 0;
        int pos = 0;
        byte[] tmpIn = Arrays.clone(in);
        long len = tmpIn.length;
        while (count < len)
        {
            String tmp = "";

            if (count + 32 >= tmpIn.length)
            {// last set of bits cannot have enough 32 bits
                for (int j = tmpIn.length - count - 1; j >= 0; j--)
                { //bin in reversed order
                    tmp += tmpIn[count + j];
                }
            }

            else
            {
                for (int j = 31; j >= 0; j--)
                { //bin in reversed order
                    tmp += tmpIn[count + j];
                }
            }

            long b = Long.parseLong(tmp, 2);
            out[pos] = (int)b & 0xffffffff;
            count += 32;
            pos++;
        }
    }

    static void resizeArray(long[] out, int sizeOutBits, long[] in, int sizeInBits, int n1n2ByteSize, int n1n2Byte64Size)
    {
        long mask = 0x7FFFFFFFFFFFFFFFl;
        int val = 0;
        if (sizeOutBits < sizeInBits)
        {
            if (sizeOutBits % 64 != 0)
            {
                val = 64 - (sizeOutBits % 64);
            }

            System.arraycopy(in, 0, out, 0, n1n2ByteSize);

            for (int i = 0; i < val; ++i)
            {
                out[n1n2Byte64Size - 1] &= (mask >> i);
            }
        }
        else
        {
            System.arraycopy(in, 0, out, 0, (sizeInBits + 7) / 8);
        }
    }

    static void fromByteArrayToBitArray(byte[] out, byte[] in)
    {
        byte[] tmpByte = Arrays.clone(in);
        String res = "";
        for (int i = 0; i < tmpByte.length; i++)
        {
            String tmp = "";
            tmp += Integer.toBinaryString(tmpByte[i] & 0xff);
            tmp = new StringBuilder(tmp).reverse().toString();

            // padding with zeros
            int gap = 0;
            if (i == tmpByte.length - 1 && tmpByte.length % 8 != 0)
            {
                if (out.length % 8 == 0)
                {
                    gap = 8 - tmp.length(); // last byte so it cannot parse to 8 bits
                }
                else
                {
                    gap = out.length % 8 - tmp.length(); // last byte so it cannot parse to 8 bits
                }
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

    static void fromUnsignedIntArrayToBitArray(byte[] out, int[] in)
    {
        int[] tmpByte = Arrays.clone(in);
        String res = "";
        for (int i = 0; i < tmpByte.length; i++)
        {
            String tmp = "";
            tmp += Integer.toBinaryString(tmpByte[i] & 0xffff);
            tmp = new StringBuilder(tmp).reverse().toString();

            // padding with zeros
            int gap = 0;
            if (i == tmpByte.length - 1 && tmpByte.length % 16 != 0)
            {
                if (out.length % 16 == 0)
                {
                    gap = 16 - tmp.length(); // last byte so it cannot parse to 8 bits
                }
                else
                {
                    gap = out.length % 16 - tmp.length(); // last byte so it cannot parse to 8 bits
                }
            }
            else
            {
                gap = 16 - tmp.length();
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

    static void fromLongArrayToBitArray(byte[] out, long[] in)
    {
        long[] tmpByte = Arrays.clone(in);
        String res = "";
        for (int i = 0; i < tmpByte.length; i++)
        {
            String tmp = "";
            tmp += Long.toUnsignedString(tmpByte[i], 2);
            tmp = new StringBuilder(tmp).reverse().toString();

            // padding with zeros
            int gap = 0;
            if (i == tmpByte.length - 1 && tmpByte.length % 64 != 0)
            {// last byte so it cannot parse to 64 bits
                if (out.length % 64 == 0)
                {
                    gap = 64 - tmp.length();
                }
                else
                {
                    gap = out.length % 64 - tmp.length();
                }
            }
            else
            {
                gap = 64 - tmp.length();
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

    static void fromLongArrayToByteArray(byte[] out, long[] in, int bitSize)
    {
        byte[] bitOut = new byte[bitSize];

        long[] tmpByte = Arrays.clone(in);
        String res = "";
        for (int i = 0; i < tmpByte.length; i++)
        {
            String tmp = "";
            tmp += Long.toUnsignedString(tmpByte[i], 2);
            tmp = new StringBuilder(tmp).reverse().toString();

            // padding with zeros
            int gap = 0;
            if (i == tmpByte.length - 1 && tmpByte.length % 64 != 0)
            {
                if (bitOut.length % 64 == 0)
                {
                    gap = 64 - tmp.length(); // last byte so it cannot parse to 64 bits
                }
                else
                {
                    gap = bitOut.length % 64 - tmp.length(); // last byte so it cannot parse to 64 bits
                }
            }
            else
            {
                gap = 64 - tmp.length();
            }
            while (gap > 0)
            {
                tmp = tmp + '0';
                gap--;
            }
            res += tmp;
        }
        fromBitStringToBytes(bitOut, res);
        fromBitArrayToByteArray(out, bitOut);

    }

    static long bitMask(long a, long b)
    {
        return ((1L << (a % b)) - 1);
    }

    static byte[] fromListOfPos1ToBitArray(int[] pos, int length)
    {
        byte[] out = new byte[length];
        for (int i = 0; i < pos.length; i++)
        {
            out[pos[i]] = 1;
        }
        return out;
    }

    static void fromByteArrayToLongArray(long[] out, byte[] in)
    {
        byte[] tmp = Arrays.clone(in);
        int r = tmp.length % 8;
        while (8 - r > 0)
        {
            tmp = Arrays.append(tmp, (byte)0);
            r++;
        }

        int off = 0;
        for (int i = 0; i < out.length; i++)
        {
            out[i] = Pack.littleEndianToLong(tmp, off);
            off += 8;
        }
    }

    static void fromByte32ArrayToLongArray(long[] out, int[] in)
    {
        byte[] bitOut = new byte[in.length * 32];

        int[] tmpByte = Arrays.clone(in);

        String res = "";
        for (int i = 0; i < tmpByte.length; i++)
        {
            String tmp = "";
            tmp += Integer.toBinaryString(tmpByte[i] & 0xffffffff);
            tmp = new StringBuilder(tmp).reverse().toString();

            // padding with zeros
            int gap = 0;
            if (i == tmpByte.length - 1 && tmpByte.length % 32 != 0)
            {
                if (bitOut.length % 32 == 0)
                {
                    gap = 32 - tmp.length(); // last byte so it cannot parse to 64 bits
                }
                else
                {
                    gap = bitOut.length % 32 - tmp.length(); // last byte so it cannot parse to 64 bits
                }
            }
            else
            {
                gap = 32 - tmp.length();
            }
            while (gap > 0)
            {
                tmp = tmp + '0';
                gap--;
            }
            res += tmp;
        }
        fromBitStringToBytes(bitOut, res);
        fromBitArrayToLongArray(out, bitOut);
    }


    static void fromLongArrayToByte32Array(int[] out, long[] in)
    {
        byte[] bitOut = new byte[in.length * 64];
        fromLongArrayToBitArray(bitOut, in);
        fromBitArrayToByte32Array(out, bitOut);
    }

    static void cloneMatrix(int[][] out, int[][] in)
    {
        for (int i = 0; i < out.length; i++)
        {
            out[i] = Arrays.clone(in[i]);
        }
    }

    static void copyBytes(int[] src, int offsetSrc, int[] dst, int offsetDst, int lengthBytes)
    {
        byte[] bits = new byte[src.length * 16];
        Utils.fromUnsignedIntArrayToBitArray(bits, src);

        byte[] copyBits = new byte[lengthBytes * 8];
        for (int i = 0; i < copyBits.length; i++)
        {
            copyBits[i] = bits[offsetSrc + i];
        }

        int[] copyInts = new int[lengthBytes / 2];
        Utils.fromBitArrayToUnsignedIntArray(copyInts, copyBits);

        System.arraycopy(copyInts, 0, dst, offsetDst, lengthBytes / 2);
    }

    static int getByteSizeFromBitSize(int size)
    {
        return (size + 7) / 8;
    }

    static int getByte64SizeFromBitSize(int size)
    {
        return (size + 63) / 64;
    }

    static int toUnsigned8bits(int a)
    {
        return a & 0xff;
    }

    static int toUnsigned16Bits(int a)
    {
        return a & 0xffff;
    }
}
