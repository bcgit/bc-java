package org.bouncycastle.pqc.crypto.falcon;

class FalconTmp
{
    static int[] byte_int(byte[] tmp)
    {
        int n = tmp.length;
        int[] res = new int[n / 4];
        for (int i = 0, j = 0; i < n / 4; i++, j += 4)
        {
            res[i] = (((int)tmp[j] & 0xFF) << 24) | (((int)tmp[j + 1] & 0xFF) << 16) | (((int)tmp[j + 2] & 0xFF) << 8) | (((int)tmp[j + 3] & 0xFF));
        }

        return res;
    }

    static byte[] int_byte(int[] tmp)
    {
        int n = tmp.length;
        byte[] res = new byte[n * 4];
        for (int i = 0; i < n; i++)
        {
            res[4 * i + 0] = (byte)((tmp[i] >>> 24) & 0xFF);
            res[4 * i + 1] = (byte)((tmp[i] >>> 16) & 0xFF);
            res[4 * i + 2] = (byte)((tmp[i] >>> 8) & 0xFF);
            res[4 * i + 3] = (byte)((tmp[i]) & 0xFF);
        }
        return res;
    }
}
