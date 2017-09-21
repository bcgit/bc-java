package org.bouncycastle.crypto.modes.gcm;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class Tables64kGCMMultiplier
    implements GCMMultiplier
{
    private byte[] H;
    private long[][][] T;

    public void init(byte[] H)
    {
        if (T == null)
        {
            T = new long[16][256][2];
        }
        else if (Arrays.areEqual(this.H, H))
        {
            return;
        }

        this.H = Arrays.clone(H);

        for (int i = 0; i < 16; ++i)
        {
            long[][] t = T[i];

            // t[0] is 0

            if (i == 0)
            {
                GCMUtil.asLongs(H, t[128]);
            }
            else
            {
                GCMUtil.multiplyP8(T[i - 1][128], t[128]);
            }

            for (int j = 64; j >= 1; j >>= 1)
            {
                GCMUtil.multiplyP(t[j + j], t[j]);
            }

            for (int j = 2; j < 256; j += j)
            {
                for (int k = 1; k < j; ++k)
                {
                    GCMUtil.xor(t[j], t[k], t[j + k]);
                }
            }
        }
    }

    public void multiplyH(byte[] x)
    {
//        long[] z = new long[2];
//        for (int i = 15; i >= 0; --i)
//        {
//            GCMUtil.xor(z, T[i][x[i] & 0xFF]);
//        }
//        Pack.longToBigEndian(z, x, 0);

        long[] t = T[15][x[15] & 0xFF];
        long z0 = t[0], z1 = t[1];

        for (int i = 14; i >= 0; --i)
        {
            t = T[i][x[i] & 0xFF];
            z0 ^= t[0];
            z1 ^= t[1];
        }

        Pack.longToBigEndian(z0, x, 0);
        Pack.longToBigEndian(z1, x, 8);
    }
}
