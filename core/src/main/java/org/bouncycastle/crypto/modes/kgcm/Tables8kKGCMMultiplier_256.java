package org.bouncycastle.crypto.modes.kgcm;

public class Tables8kKGCMMultiplier_256
    implements KGCMMultiplier
{
    private long[][] T;

    public void init(long[] H)
    {
        if (T == null)
        {
            T = new long[256][KGCMUtil_256.SIZE];
        }
        else if (KGCMUtil_256.equal(H, T[1]))
        {
            return;
        }

        // T[0] = 0

        // T[1] = H
        KGCMUtil_256.copy(H, T[1]);

        for (int e = 2; e < 256; e += 2)
        {
            // T[2.n] = 2.T[n]
            KGCMUtil_256.double1x(T[e >> 1], T[e]);

            // T[2.n + 1] = T[2.n] + T[1]
            KGCMUtil_256.add(T[e], T[1], T[e + 1]);
        }
    }

    public void multiplyH(long[] z)
    {
        long[] r = new long[KGCMUtil_256.SIZE];
        KGCMUtil_256.copy(T[(int)(z[KGCMUtil_256.SIZE - 1] >>> 56) & 0xFF], r);
        for (int i = (KGCMUtil_256.SIZE << 3) - 2; i >= 0; --i)
        {
            KGCMUtil_256.double8x(r, r);
            KGCMUtil_256.add(T[(int)(z[i >>> 3] >>> ((i & 7) << 3)) & 0xFF], r, r);
        }
        KGCMUtil_256.copy(r, z);
    }
}
