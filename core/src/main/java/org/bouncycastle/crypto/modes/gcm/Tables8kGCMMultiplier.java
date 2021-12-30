package org.bouncycastle.crypto.modes.gcm;

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
            T = new long[2][256][2];
        }
        else if (0 != GCMUtil.areEqual(this.H, H))
        {
            return;
        }

        this.H = new byte[GCMUtil.SIZE_BYTES];
        GCMUtil.copy(H, this.H);

        for (int i = 0; i < 2; ++i)
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
        long[][] T0 = T[0], T1 = T[1];

//        long[] z = new long[2];
//        for (int i = 14; i >= 0; i -= 2)
//        {
//            GCMUtil.multiplyP16(z);
//            GCMUtil.xor(z, T0[x[i] & 0xFF]);
//            GCMUtil.xor(z, T1[x[i + 1] & 0xFF]);
//        }
//        Pack.longToBigEndian(z, x, 0);

        long[] u = T0[x[14] & 0xFF];
        long[] v = T1[x[15] & 0xFF];
        long z0 = u[0] ^ v[0], z1 = u[1] ^ v[1];

        for (int i = 12; i >= 0; i -= 2)
        {
            u = T0[x[i] & 0xFF];
            v = T1[x[i + 1] & 0xFF];

            long c = z1 << 48;
            z1 = u[1] ^ v[1] ^ ((z1 >>> 16) | (z0 << 48));
            z0 = u[0] ^ v[0] ^ (z0 >>> 16) ^ c ^ (c >>> 1) ^ (c >>> 2) ^ (c >>> 7);
        }

        Pack.longToBigEndian(z0, x, 0);
        Pack.longToBigEndian(z1, x, 8);
   }
}
