package org.bouncycastle.crypto.modes.gcm;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class Tables4kGCMMultiplier
    implements GCMMultiplier
{
    private byte[] H;
    private long[][] T;

    public void init(byte[] H)
    {
        if (T == null)
        {
            T = new long[256][2];
        }
        else if (Arrays.areEqual(this.H, H))
        {
            return;
        }

        this.H = Arrays.clone(H);

        // T[0] is 0

        GCMUtil.asLongs(H, T[128]);

        for (int j = 64; j >= 1; j >>= 1)
        {
            GCMUtil.multiplyP(T[j + j], T[j]);
        }

        for (int j = 2; j < 256; j += j)
        {
            for (int k = 1; k < j; ++k)
            {
                GCMUtil.xor(T[j], T[k], T[j + k]);
            }
        }
    }

    public void multiplyH(byte[] x)
    {
//        long[] z = new long[2];
//        GCMUtil.copy(T[x[15] & 0xFF], z);
//        for (int i = 14; i >= 0; --i)
//        {
//            GCMUtil.multiplyP8(z);
//            GCMUtil.xor(z, T[x[i] & 0xFF]);
//        }
//        Pack.longToBigEndian(z, x, 0);

        long[] t = T[x[15] & 0xFF];
        long z0 = t[0], z1 = t[1];

        for (int i = 14; i >= 0; --i)
        {
            t = T[x[i] & 0xFF];

            long c = z1 << 56;
            z1 = t[1] ^ ((z1 >>> 8) | (z0 << 56));
            z0 = t[0] ^ (z0 >>> 8) ^ c ^ (c >>> 1) ^ (c >>> 2) ^ (c >>> 7);
        }

        Pack.longToBigEndian(z0, x, 0);
        Pack.longToBigEndian(z1, x, 8);
    }
}
