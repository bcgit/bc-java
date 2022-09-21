package org.bouncycastle.pqc.crypto.hqc;

import org.bouncycastle.util.Pack;

class Utils
{
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

    static void fromBitArrayToLongArray(long[] out, byte[] in)
    {
        int count = 0;
        int pos = 0;
        long len = in.length;
        while (count < len)
        {
            if (count + 64 >= in.length)
            {// last set of bits cannot have enough 8 bits
                long b = in[count];
                for (int j = in.length - count - 1; j >= 1; j--)
                { //bin in reversed order
                    b |= ((long)in[count + j]) << j;
                }
                out[pos] = b;
            }
            else
            {
                long b = in[count];
                for (int j = 63; j >= 1; j--)
                { //bin in reversed order
                    b |= ((long)in[count + j]) << j;
                }
                out[pos] = b;
            }

            count += 64;
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

    static void fromLongArrayToBitArray(byte[] out, long[] in)
    {
        int max = (out.length / 64);
        for (int i = 0; i < max; i++)
        {
            for (int j = 0; j != 64; j++)
            {
                out[i * 64 + j] = (byte)((in[i] & (1L << j)) >>> j);
            }
        }
        if (out.length % 64 != 0)
        {
            int off = max * 64;
            int count = 0;
            while (off < out.length)
            {
                out[off++] = (byte)((in[max] & (1L << count)) >>> count);
                count++;
            }
        }
    }

    static void fromLongArrayToByteArray(byte[] out, long[] in, int bitSize)
    {
        int max = out.length / 8;
        for (int i = 0; i != max; i++)
        {
            Pack.longToLittleEndian(in[i], out, i * 8);
        }

        if (out.length % 8 != 0)
        {
            int off = max * 8;
            int count = 0;
            while (off < out.length)
            {
                out[off++] = (byte)(in[max] >>> (count++ * 8));
            }
        }
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
        byte[] tmp = in;
        if (in.length % 8 != 0)
        {
            tmp = new byte[((in.length + 7) / 8) * 8];
            System.arraycopy(in, 0, tmp, 0, in.length);
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
        for (int i = 0; i != in.length; i += 2)
        {
            out[i / 2] = in[i] & 0xffffffffL;
            out[i / 2] |= (long)in[i + 1] << 32;
        }
    }

    static void fromLongArrayToByte32Array(int[] out, long[] in)
    {
        for (int i = 0; i != in.length; i++)
        {
            out[2 * i] = (int)in[i];
            out[2 * i + 1] = (int)(in[i] >> 32);
        }
    }

    static void copyBytes(int[] src, int offsetSrc, int[] dst, int offsetDst, int lengthBytes)
    {
        System.arraycopy(src, offsetSrc, dst, offsetDst, lengthBytes / 2);
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
