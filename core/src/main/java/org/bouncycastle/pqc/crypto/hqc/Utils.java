package org.bouncycastle.pqc.crypto.hqc;

import org.bouncycastle.util.Pack;

class Utils
{
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

    static void fromLongArrayToByteArray(byte[] out, int outOff, int outLen, long[] in)
    {
        int max = outLen >> 3;
        for (int i = 0; i != max; i++)
        {
            Pack.longToLittleEndian(in[i], out, outOff);
            outOff += 8;
        }

        if ((outLen & 7) != 0)
        {
            int count = 0;
            while (outOff < out.length)
            {
                out[outOff++] = (byte)(in[max] >>> (count++ * 8));
            }
        }
    }

    static long bitMask(long a, long b)
    {
        return ((1L << (a % b)) - 1);
    }

    static void fromByteArrayToLongArray(long[] out, byte[] in, int off, int inLen)
    {
        byte[] tmp = in;
        if (inLen % 8 != 0)
        {
            tmp = new byte[((inLen + 7) / 8) * 8];
            System.arraycopy(in, off, tmp, 0, inLen);
            off = 0;
        }

        int len = Math.min(out.length, (inLen + 7) >>> 3);
        for (int i = 0; i < len; i++)
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
