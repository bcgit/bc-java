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

        for (int i = 0; i < 32; ++i)
        {
            long[][] t = T[i];

            // t[0] = 0

            if (i == 0)
            {
                // t[1] = H.p^3
                GCMUtil.asLongs(this.H, t[1]);
                GCMUtil.multiplyP3(t[1], t[1]);
            }
            else
            {
                // t[1] = T[i-1][1].p^4
                GCMUtil.multiplyP4(T[i - 1][1], t[1]);
            }

            for (int n = 2; n < 16; n += 2)
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
//            GCMUtil.xor(z, T[i + i + 1][(x[i] & 0x0F)]);
//            GCMUtil.xor(z, T[i + i    ][(x[i] & 0xF0) >>> 4]);
//        }
//        Pack.longToBigEndian(z, x, 0);

        long z0 = 0, z1 = 0;

        for (int i = 15; i >= 0; --i)
        {
            long[] u = T[i + i + 1][(x[i] & 0x0F)];
            long[] v = T[i + i    ][(x[i] & 0xF0) >>> 4];

            z0 ^= u[0] ^ v[0];
            z1 ^= u[1] ^ v[1];
        }

        Pack.longToBigEndian(z0, x, 0);
        Pack.longToBigEndian(z1, x, 8);
   }
}
