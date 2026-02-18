package org.bouncycastle.pqc.crypto.hqc;

import org.bouncycastle.util.Pack;

class Utils
{
    static void fromLongArrayToByteArray(byte[] out, int outOff, int outLen, long[] in)
    {
        int nsLen = outLen >> 3;
        Pack.longToLittleEndian(in, 0, nsLen, out, outOff);

        int partial = outLen & 7;
        if (partial != 0)
        {
            Pack.longToLittleEndian_Low(in[nsLen], out, outOff + outLen - partial, partial);
        }
    }

    static void fromByteArrayToLongArray(long[] out, byte[] in, int inOff, int inLen)
    {
        int nsLen = inLen >> 3;
        Pack.littleEndianToLong(in, inOff, out, 0, nsLen);

        int partial = inLen & 7;
        if (partial != 0)
        {
            out[nsLen] = Pack.littleEndianToLong_Low(in, inOff + inLen - partial, partial);
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
