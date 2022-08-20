package org.bouncycastle.pqc.crypto.falcon;

class FalconConversions
{

    FalconConversions()
    {
    }

    byte[] int_to_bytes(int x)
    {
        byte[] res = new byte[4];
        res[0] = (byte)(x >>> 0);
        res[1] = (byte)(x >>> 8);
        res[2] = (byte)(x >>> 16);
        res[3] = (byte)(x >>> 24);
        return res;
    }

    int bytes_to_int(byte[] src, int pos)
    {
        int acc = 0;
        acc = toUnsignedInt(src[pos + 0]) << 0 |
            toUnsignedInt(src[pos + 1]) << 8 |
            toUnsignedInt(src[pos + 2]) << 16 |
            toUnsignedInt(src[pos + 3]) << 24;
        return acc;
    }

    int[] bytes_to_int_array(byte[] src, int pos, int num)
    {
        int[] res = new int[num];
        for (int i = 0; i < num; i++)
        {
            res[i] = bytes_to_int(src, pos + (4 * i));
        }
        return res;
    }

    byte[] long_to_bytes(long x)
    {
        byte[] res = new byte[8];
        res[0] = (byte)(x >>> 0);
        res[1] = (byte)(x >>> 8);
        res[2] = (byte)(x >>> 16);
        res[3] = (byte)(x >>> 24);
        res[4] = (byte)(x >>> 32);
        res[5] = (byte)(x >>> 40);
        res[6] = (byte)(x >>> 48);
        res[7] = (byte)(x >>> 56);
        return res;
    }

    long bytes_to_long(byte[] src, int pos)
    {
        long acc = 0;
        acc = toUnsignedLong(src[pos + 0]) << 0 |
            toUnsignedLong(src[pos + 1]) << 8 |
            toUnsignedLong(src[pos + 2]) << 16 |
            toUnsignedLong(src[pos + 3]) << 24 |
            toUnsignedLong(src[pos + 4]) << 32 |
            toUnsignedLong(src[pos + 5]) << 40 |
            toUnsignedLong(src[pos + 6]) << 48 |
            toUnsignedLong(src[pos + 7]) << 56;
        return acc;
    }
    
    private int toUnsignedInt(byte b)
    {
        return b & 0xff;
    }
    
    private long toUnsignedLong(byte b)
    {
        return b & 0xffL;
    }
}
