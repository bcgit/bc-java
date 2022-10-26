package org.bouncycastle.pqc.crypto.hqc;

import org.bouncycastle.util.Pack;

class Utils
{
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

    static void fromByte16ArrayToLongArray(long[] output, int[] input)
    {
        for (int i = 0; i != input.length; i += 4)
        {
            output[i / 4] = (long)input[i] & 0xffffL;
            output[i / 4] |= (long)input[i + 1] << 16;
            output[i / 4] |= (long)input[i + 2] << 32;
            output[i / 4] |= (long)input[i + 3] << 48;
        }
    }

    static void fromByteArrayToByte16Array(int[] output, byte[] input)
    {
        byte[] tmp = input;
        if (input.length % 2 != 0)
        {
            tmp = new byte[((input.length + 1) / 2) * 2];
            System.arraycopy(input, 0, tmp, 0, input.length);
        }

        int off = 0;
        for (int i = 0; i < output.length; i++)
        {
            output[i] = (int)Pack.littleEndianToShort(tmp, off) & 0xffff;
            off += 2;
        }
    }

    static void fromLongArrayToByteArray(byte[] out, long[] in)
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

    static void xorLongToByte16Array(int[] output, long input, int startIndex)
    {
        output[startIndex + 0] ^= (int)input & 0xffff;
        output[startIndex + 1] ^= (int)(input >>> 16) & 0xffff;
        output[startIndex + 2] ^= (int)(input >>> 32) & 0xffff;
        output[startIndex + 3] ^= (int)(input >>> 48) & 0xffff;
    }
}
