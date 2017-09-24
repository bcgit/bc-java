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

            // t[0] = 0

            if (i == 0)
            {
                // t[1] = H.p^7
                GCMUtil.asLongs(this.H, t[1]);
                GCMUtil.multiplyP7(t[1], t[1]);
            }
            else
            {
                // t[1] = T[i-1][1].p^8
                GCMUtil.multiplyP8(T[i - 1][1], t[1]);
            }

            for (int n = 2; n < 256; n += 2)
            {
                // t[2.n] = t[n].p^-1
                GCMUtil.divideP(t[n >> 1], t[n]);

                // t[2.n + 1] = t[2.n] + t[1]
                GCMUtil.xor(t[n], t[1], t[n + 1]);
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
