package org.bouncycastle.crypto.modes.kgcm;

public class Tables16kKGCMMultiplier_512
    implements KGCMMultiplier
{
    private long[][] T;

    public void init(long[] H)
    {
        if (T == null)
        {
            T = new long[256][KGCMUtil_512.SIZE];
        }
        else if (KGCMUtil_512.equal(H, T[1]))
        {
            return;
        }

        // T[0] = 0

        // T[1] = H
        KGCMUtil_512.copy(H, T[1]);

        for (int n = 2; n < 256; n += 2)
        {
            // T[2.n] = x.T[n]
            KGCMUtil_512.multiplyX(T[n >> 1], T[n]);

            // T[2.n + 1] = T[2.n] + T[1]
            KGCMUtil_512.add(T[n], T[1], T[n + 1]);
        }
    }

    public void multiplyH(long[] z)
    {
        long[] r = new long[KGCMUtil_512.SIZE];
        KGCMUtil_512.copy(T[(int)(z[KGCMUtil_512.SIZE - 1] >>> 56) & 0xFF], r);
        for (int i = (KGCMUtil_512.SIZE << 3) - 2; i >= 0; --i)
        {
            KGCMUtil_512.multiplyX8(r, r);
            KGCMUtil_512.add(T[(int)(z[i >>> 3] >>> ((i & 7) << 3)) & 0xFF], r, r);
        }
        KGCMUtil_512.copy(r, z);
    }
}
