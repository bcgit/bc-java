package org.bouncycastle.crypto.modes.gcm;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class Tables8kGCMMultiplier
    implements GCMMultiplier
{
    private byte[] H;
    private long[][][] T;

    public void init(byte[] H)
    {
        if (T == null)
        {
            T = new long[32][16][2];
        }
        else if (Arrays.areEqual(this.H, H))
        {
            return;
        }

        this.H = Arrays.clone(H);

        // T[0][0] is 0
        // T[1][0] is 0

        GCMUtil.asLongs(H, T[1][8]);

        for (int j = 4; j >= 1; j >>= 1)
        {
            GCMUtil.multiplyP(T[1][j + j], T[1][j]);
        }

        GCMUtil.multiplyP(T[1][1], T[0][8]);

        for (int j = 4; j >= 1; j >>= 1)
        {
            GCMUtil.multiplyP(T[0][j + j], T[0][j]);
        }

        int i = 0;
        for (;;)
        {
            for (int j = 2; j < 16; j += j)
            {
                for (int k = 1; k < j; ++k)
                {
                    GCMUtil.xor(T[i][j], T[i][k], T[i][j + k]);
                }
            }

            if (++i == 32)
            {
                return;
            }

            if (i > 1)
            {
                // T[i][0] is 0;
                for(int j = 8; j > 0; j >>= 1)
                {
                    GCMUtil.multiplyP8(T[i - 2][j], T[i][j]);
                }
            }
        }
    }

    public void multiplyH(byte[] x)
    {
//        long[] z = new long[2];
//        for (int i = 15; i >= 0; --i)
//        {
//            GCMUtil.xor(z, T[i + i][x[i] & 0x0F]);
//            GCMUtil.xor(z, T[i + i + 1][(x[i] & 0xF0) >>> 4]);
//        }
//        Pack.longToBigEndian(z, x, 0);

        long z0 = 0, z1 = 0;

        for (int i = 15; i >= 0; --i)
        {
            long[] u = T[i + i][x[i] & 0x0F];
            long[] v = T[i + i + 1][(x[i] & 0xF0) >>> 4];

            z0 ^= u[0] ^ v[0];
            z1 ^= u[1] ^ v[1];
        }

        Pack.longToBigEndian(z0, x, 0);
        Pack.longToBigEndian(z1, x, 8);
   }
}
