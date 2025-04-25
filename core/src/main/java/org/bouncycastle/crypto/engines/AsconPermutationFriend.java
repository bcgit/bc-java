package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.digests.ISAPDigest;
import org.bouncycastle.util.Longs;

public class AsconPermutationFriend
{
    public static AsconPermutation getAsconPermutation(ISAPDigest.Friend friend)
    {
        if (null == friend)
        {
            throw new NullPointerException("This method is only for use by ISAPDigest or Ascon Digest");
        }
        return new AsconPermutation();
    }

    public static class AsconPermutation
    {
        AsconPermutation()
        {
        }

        public long x0;
        public long x1;
        public long x2;
        public long x3;
        public long x4;

        public void round(long C)
        {
            x2 ^= C;
            long x0x4 = x0 ^ x4;
            //long x0x2c = x0 ^ x2;
            long x1x2c = x1 ^ x2;
            long x1orx2c = x1 | x2;
            long t0 = x3 ^ x1orx2c ^ x0 ^ (x1 & x0x4);
            //long t1 = x0x4 ^ x2 ^ x3 ^ (x1x2c & (x1 ^ x3));
            long t1 = x0x4 ^ (x1orx2c | x3) ^ (x1 & x2 & x3);
            long t2 = x1x2c ^ (x4 & (~x3));//x4 ^ (x3 & x4);
            //long t3 = x0 ^ x1x2c ^ ((~x0) & (x3 ^ x4));
            long t3 = (x0 | (x3 ^ x4)) ^ x1x2c;
            //long t4 = x1 ^ x3 ^ x4 ^ (x0x4 & x1);
            long t4 = x3 ^ (x1 | x4) ^ (x0 & x1);
            x0 = t0 ^ Longs.rotateRight(t0, 19) ^ Longs.rotateRight(t0, 28);
            x1 = t1 ^ Longs.rotateRight(t1, 39) ^ Longs.rotateRight(t1, 61);
            x2 = ~(t2 ^ Longs.rotateRight(t2, 1) ^ Longs.rotateRight(t2, 6));
            x3 = t3 ^ Longs.rotateRight(t3, 10) ^ Longs.rotateRight(t3, 17);
            x4 = t4 ^ Longs.rotateRight(t4, 7) ^ Longs.rotateRight(t4, 41);
        }

        public void p(int nr)
        {
            if (nr == 12)
            {
                round(0xf0L);
                round(0xe1L);
                round(0xd2L);
                round(0xc3L);
            }
            if (nr >= 8)
            {
                round(0xb4L);
                round(0xa5L);
            }
            round(0x96L);
            round(0x87L);
            round(0x78L);
            round(0x69L);
            round(0x5aL);
            round(0x4bL);
        }

        public void set(long x0, long x1, long x2, long x3, long x4)
        {
            this.x0 = x0;
            this.x1 = x1;
            this.x2 = x2;
            this.x3 = x3;
            this.x4 = x4;
        }
    }
}
