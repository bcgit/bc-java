package org.bouncycastle.pqc.crypto.falcon;

class FalconSmallPoly
{
    byte[] coeffs;

    FalconSmallPoly(int n)
    {
        this.coeffs = new byte[n];
    }

    FalconSmallPoly(byte[] f)
    {
        this.coeffs = f.clone();
    }

    static FalconSmallPolyRes big_to_small(FalconBigPoly s, int lim, int logn)
    {
        int n, u;
        n = 1 << logn;
        FalconSmallPoly f = new FalconSmallPoly(n);
        for (u = 0; u < n; u++)
        {
            int z;
            z = s.coeffs[u].one_to_plain();
            if (z < -lim || z > lim)
            {
                return new FalconSmallPolyRes();
            }
            f.coeffs[u] = (byte)z;
        }
        return new FalconSmallPolyRes(f);
    }

    void poly_mkgauss(FalconSHAKE256 random, int logn)
    {
        int n, u;
        int mod2;
        n = 1 << logn;
        mod2 = 0;
        for (u = 0; u < n; u++)
        {
            int s;
            while (true)
            {
                s = mkgauss(logn, random);
                if (s < -127 || s > 127)
                {
                    continue;
                }
                if (u == n - 1)
                {
                    if ((mod2 ^ (s & 1)) == 0)
                    {
                        continue;
                    }
                }
                else
                {
                    mod2 ^= (s & 1);
                }
                this.coeffs[u] = (byte)s;
                break;
            }
        }
    }

    /*
     * Generate a random value with a Gaussian distribution centered on 0.
     * The RNG must be ready for extraction (already flipped).
     *
     * Distribution has standard deviation 1.17*sqrt(q/(2*N)). The
     * precomputed table is for N = 1024. Since the sum of two independent
     * values of standard deviation sigma has standard deviation
     * sigma*sqrt(2), then we can just generate more values and add them
     * together for lower dimensions.
     */
    private int mkgauss(int logn, FalconSHAKE256 random)
    {
        int g, val;
        g = 1 << (10 - logn);
        val = 0;
        for (int u = 0; u < g; u++)
        {
            long r;
            int f, v, k, neg;

            /*
             * First value:
             *  - flag 'neg' is randomly selected to be 0 or 1.
             *  - flag 'f' is set to 1 if the generated value is zero,
             *    or set to 0 otherwise.
             */
            r = random.nextLong();
            neg = (int)(r >>> 63);
            r &= ~((long)1 << 63);
            f = (int)((r - gauss_1024_12289[0]) >>> 63);

            /*
             * We produce a new random 63-bit integer r, and go over
             * the array, starting at index 1. We store in v the
             * index of the first array element which is not greater
             * than r, unless the flag f was already 1.
             */
            v = 0;
            r = random.nextLong();
            r &= ~((long)1 << 63);
            for (k = 1; k < gauss_1024_12289.length; k++)
            {
                int t;

                t = (int)((r - gauss_1024_12289[k]) >>> 63) ^ 1;
                v |= k & -(t & (f ^ 1));
                f |= t;
            }

            /*
             * We apply the sign ('neg' flag). If the value is zero,
             * the sign has no effect.
             */
            v = (v ^ -neg) + neg;

            /*
             * Generated value is added to val.
             */
            val += v;
        }
        return val;
    }

    private static final long gauss_1024_12289[] = {
        Long.parseUnsignedLong("1283868770400643928"), Long.parseUnsignedLong("6416574995475331444"), Long.parseUnsignedLong("4078260278032692663"),
        Long.parseUnsignedLong("2353523259288686585"), Long.parseUnsignedLong("1227179971273316331"), Long.parseUnsignedLong("575931623374121527"),
        Long.parseUnsignedLong("242543240509105209"), Long.parseUnsignedLong("91437049221049666"), Long.parseUnsignedLong("30799446349977173"),
        Long.parseUnsignedLong("9255276791179340"), Long.parseUnsignedLong("2478152334826140"), Long.parseUnsignedLong("590642893610164"),
        Long.parseUnsignedLong("125206034929641"), Long.parseUnsignedLong("23590435911403"), Long.parseUnsignedLong("3948334035941"),
        Long.parseUnsignedLong("586753615614"), Long.parseUnsignedLong("77391054539"), Long.parseUnsignedLong("9056793210"),
        Long.parseUnsignedLong("940121950"), Long.parseUnsignedLong("86539696"), Long.parseUnsignedLong("7062824"),
        Long.parseUnsignedLong("510971"), Long.parseUnsignedLong("32764"), Long.parseUnsignedLong("1862"),
        Long.parseUnsignedLong("94"), Long.parseUnsignedLong("4"), Long.parseUnsignedLong("0")
    };

    int sqnorm(int logn)
    {
        int n, u;
        int s, ng;

        n = 1 << logn;
        s = 0;
        ng = 0;
        for (u = 0; u < n; u++)
        {
            int z;

            z = this.coeffs[u];
            s += z * z;
            ng |= s;
        }
        return s | -(ng >>> 31);
    }

    static boolean big_to_small(FalconSmallPoly d, int s, int[] sdata, int lim, int logn)
    {
        int n, u;

        n = 1 << logn;
        for (u = 0; u < n; u++)
        {
            int z;

            z = FalconBigInt.one_to_plain(s + u, sdata);
            if (z < -lim || z > lim)
            {
                return false;
            }
            d.coeffs[u] = (byte)z;
        }
        return true;
    }
}
