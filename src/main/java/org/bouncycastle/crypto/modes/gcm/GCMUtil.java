package org.bouncycastle.crypto.modes.gcm;

import org.bouncycastle.crypto.util.Pack;
import org.bouncycastle.util.Arrays;

abstract class GCMUtil
{
    static byte[] oneAsBytes()
    {
        byte[] tmp = new byte[16];
        tmp[0] = (byte)0x80;
        return tmp;
    }

    static int[] oneAsInts()
    {
        int[] tmp = new int[4];
        tmp[0] = 0x80000000;
        return tmp;
    }

    static byte[] asBytes(int[] ns)
    {
        byte[] output = new byte[16];
        Pack.intToBigEndian(ns, output, 0);
        return output;
    }

    static int[] asInts(byte[] bs)
    {
        int[] output = new int[4];
        Pack.bigEndianToInt(bs, 0, output);
        return output;
    }

    static void asInts(byte[] bs, int[] output)
    {
        Pack.bigEndianToInt(bs, 0, output);
    }

    static void multiply(byte[] block, byte[] val)
    {
        byte[] tmp = Arrays.clone(block);
        byte[] c = new byte[16];

        for (int i = 0; i < 16; ++i)
        {
            byte bits = val[i];
            for (int j = 7; j >= 0; --j)
            {
                if ((bits & (1 << j)) != 0)
                {
                    xor(c, tmp);
                }

                boolean lsb = (tmp[15] & 1) != 0;
                shiftRight(tmp);
                if (lsb)
                {
                    // R = new byte[]{ 0xe1, ... };
//                    GCMUtil.xor(v, R);
                    tmp[0] ^= (byte)0xe1;
                }
            }
        }

        System.arraycopy(c, 0, block, 0, 16);
    }

    // P is the value with only bit i=1 set
    static void multiplyP(int[] x)
    {
        boolean lsb = (x[3] & 1) != 0;
        shiftRight(x);
        if (lsb)
        {
            // R = new int[]{ 0xe1000000, 0, 0, 0 };
//            xor(v, R);
            x[0] ^= 0xe1000000;
        }
    }

    static void multiplyP(int[] x, int[] output)
    {
        boolean lsb = (x[3] & 1) != 0;
        shiftRight(x, output);
        if (lsb)
        {
            output[0] ^= 0xe1000000;
        }
    }

    // P is the value with only bit i=1 set
    static void multiplyP8(int[] x)
    {
//        for (int i = 8; i != 0; --i)
//        {
//            multiplyP(x);
//        }

        int lsw = x[3];
        shiftRightN(x, 8);
        for (int i = 7; i >= 0; --i)
        {
            if ((lsw & (1 << i)) != 0)
            {
                x[0] ^= (0xe1000000 >>> (7 - i));
            }
        }
    }

    static void multiplyP8(int[] x, int[] output)
    {
        int lsw = x[3];
        shiftRightN(x, 8, output);
        for (int i = 7; i >= 0; --i)
        {
            if ((lsw & (1 << i)) != 0)
            {
                output[0] ^= (0xe1000000 >>> (7 - i));
            }
        }
    }

    static void shiftRight(byte[] block)
    {
        int i = 0;
        int bit = 0;
        for (;;)
        {
            int b = block[i] & 0xff;
            block[i] = (byte) ((b >>> 1) | bit);
            if (++i == 16)
            {
                break;
            }
            bit = (b & 1) << 7;
        }
    }

    static void shiftRight(byte[] block, byte[] output)
    {
        int i = 0;
        int bit = 0;
        for (;;)
        {
            int b = block[i] & 0xff;
            output[i] = (byte) ((b >>> 1) | bit);
            if (++i == 16)
            {
                break;
            }
            bit = (b & 1) << 7;
        }
    }

    static void shiftRight(int[] block)
    {
        int i = 0;
        int bit = 0;
        for (;;)
        {
            int b = block[i];
            block[i] = (b >>> 1) | bit;
            if (++i == 4)
            {
                break;
            }
            bit = b << 31;
        }
    }

    static void shiftRight(int[] block, int[] output)
    {
        int i = 0;
        int bit = 0;
        for (;;)
        {
            int b = block[i];
            output[i] = (b >>> 1) | bit;
            if (++i == 4)
            {
                break;
            }
            bit = b << 31;
        }
    }

    static void shiftRightN(int[] block, int n)
    {
        int i = 0;
        int bits = 0;
        for (;;)
        {
            int b = block[i];
            block[i] = (b >>> n) | bits;
            if (++i == 4)
            {
                break;
            }
            bits = b << (32 - n);
        }
    }

    static void shiftRightN(int[] block, int n, int[] output)
    {
        int i = 0;
        int bits = 0;
        for (;;)
        {
            int b = block[i];
            output[i] = (b >>> n) | bits;
            if (++i == 4)
            {
                break;
            }
            bits = b << (32 - n);
        }
    }

    static void xor(byte[] block, byte[] val)
    {
        for (int i = 15; i >= 0; --i)
        {
            block[i] ^= val[i];
        }
    }

    static void xor(byte[] block, byte[] val, int off, int len)
    {
        while (len-- > 0)
        {
            block[len] ^= val[off + len];
        }
    }

    static void xor(byte[] block, byte[] val, byte[] output)
    {
        for (int i = 15; i >= 0; --i)
        {
            output[i] = (byte)(block[i] ^ val[i]);
        }
    }

    static void xor(int[] block, int[] val)
    {
        for (int i = 3; i >= 0; --i)
        {
            block[i] ^= val[i];
        }
    }

    static void xor(int[] block, int[] val, int[] output)
    {
        for (int i = 3; i >= 0; --i)
        {
            output[i] = block[i] ^ val[i];
        }
    }
}
