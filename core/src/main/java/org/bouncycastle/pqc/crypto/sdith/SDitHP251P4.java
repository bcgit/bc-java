package org.bouncycastle.pqc.crypto.sdith;

/**
 * GF(p251^4) arithmetic for SDitH p251 variants, port of the reference p251p4.c.
 * <p>
 * Tower-field construction (matching IRRED_CST_P251P2 = 2 and
 * IRRED_CST_P251P4 = 0x101 = X + 1):
 * <ul>
 *   <li>GF(p251^2) = GF(p251)[X] / (X^2 - 2), generator 0x2984.</li>
 *   <li>GF(p251^4) = GF(p251^2)[Y] / (Y^2 - (X + 1)), generator 0x703d9e62.</li>
 * </ul>
 * Log/exp tables are built lazily.
 */
final class SDitHP251P4
{
    static final int IRRED_CST_P251P2 = 2;
    static final int IRRED_CST_P251P4 = 0x101;
    static final int GEN_P251P4 = 0x703d9e62;
    static final int GEN_P251P2 = 0x2984;

    static final int ORDER_P251P2 = 63000;
    static final long ORDER_P251P4 = 3969126000L;
    static final int PP_POWER_P251P4 = 63002;
    static final int PP_POWER_P251P2 = 252;

    private static final char[] LOG16 = new char[65536];
    private static final char[] EXP16 = new char[ORDER_P251P2 + 1];
    private static final int[] LOG1_32 = new int[ORDER_P251P2 + 1];
    private static final char[] EXP1_32_U = new char[PP_POWER_P251P4];
    private static final char[] EXP1_32_V = new char[PP_POWER_P251P4];

    static
    {
        initP251P2Tables();
        initP251P4Tables();
    }

    private SDitHP251P4()
    {
    }

    static int mulNaive16(int x, int y)
    {
        x &= 0xffff;
        y &= 0xffff;
        int xx0 = x & 0xff;
        int xx1 = (x >>> 8) & 0xff;
        int yy0 = y & 0xff;
        int yy1 = (y >>> 8) & 0xff;
        int z0 = SDitHP251.mulNaive(xx0, yy0);
        int z1 = SDitHP251.mulNaive(xx0, yy1) + SDitHP251.mulNaive(xx1, yy0);
        int z2 = SDitHP251.mulNaive(xx1, yy1);
        z0 += IRRED_CST_P251P2 * z2;
        return SDitHP251.reduce16(z0) | (SDitHP251.reduce16(z1) << 8);
    }

    /**
     * Flattened GF(251^4) multiplication, port of the optimized reference's
     * gf251to4.c (Optimized_Implementation, threshold tree). Same tower as the
     * nested form this replaces — X^2 = 2, Y^2 = X + 1 — but the two levels of
     * Karatsuba are expanded into a single formula: 9 widening base-field
     * multiplications with reduction deferred to 4 final reduce32 calls,
     * instead of 16 base multiplications with reductions at every tower level.
     * Byte-identical output; constant-time (no tables, no branches). The
     * inline bound comments track the unreduced magnitudes for canonical
     * lanes (p = 251, p^2 = 63001); the maximum, 36 p^2 = 2268036, stays far
     * below 2^31 even when lanes run to 255 (a further ~3.3% headroom). The
     * added multiples of p^2 keep intermediates non-negative and vanish mod p.
     */
    static int mulNaive(int x, int y)
    {
        final int p = 251;
        final int p2 = p * p;

        int a0 = x & 0xff;
        int a1 = (x >>> 8) & 0xff;
        int a2 = (x >>> 16) & 0xff;
        int a3 = (x >>> 24) & 0xff;
        int b0 = y & 0xff;
        int b1 = (y >>> 8) & 0xff;
        int b2 = (y >>> 16) & 0xff;
        int b3 = (y >>> 24) & 0xff;

        int mAb0 = a0 * b0;                                       // <= p^2
        int mAb1 = a1 * b1;                                       // <= p^2
        int mAb2 = a2 * b2;                                       // <= p^2
        int mAb3 = a3 * b3;                                       // <= p^2
        int aA01 = a0 + a1;                                       // <= 2p
        int aA23 = a2 + a3;                                       // <= 2p
        int aA02 = a0 + a2;                                       // <= 2p
        int aA13 = a1 + a3;                                       // <= 2p
        int aB01 = b0 + b1;                                       // <= 2p
        int aB23 = b2 + b3;                                       // <= 2p
        int aB02 = b0 + b2;                                       // <= 2p
        int aB13 = b1 + b3;                                       // <= 2p

        int cnst0 = 2 * mAb1 + mAb0;                              // <= 3 p^2
        int cnst1 = aA01 * aB01 + 2 * p2 - mAb1 - mAb0;           // <= 6 p^2
        int leading0 = 2 * mAb3 + mAb2;                           // <= 3 p^2
        int leading1 = aA23 * aB23 + 2 * p2 - mAb3 - mAb2;        // <= 6 p^2
        int cnstSum = aA02 * aB02;                                // <= 4 p^2
        int leadingSum = aA13 * aB13;                             // <= 4 p^2
        int aA01234 = aA01 + aA23;                                // <= 4p
        int aB01234 = aB01 + aB23;                                // <= 4p

        int aCnstLeading0 = leading0 + cnst0;                     // <= 6 p^2
        int aCnstLeading1 = leading1 + cnst1;                     // <= 12 p^2

        int res0 = 2 * leading1 + aCnstLeading0;                  // <= 18 p^2
        int res1 = aCnstLeading1 + leading0;                      // <= 15 p^2
        int res2 = 2 * leadingSum + cnstSum + 6 * p2 - aCnstLeading0;                       // <= 18 p^2
        int res3 = aA01234 * aB01234 + 20 * p2 - leadingSum - cnstSum - aCnstLeading1;      // <= 36 p^2

        return SDitHP251.reduce32(res0)
            | (SDitHP251.reduce32(res1) << 8)
            | (SDitHP251.reduce32(res2) << 16)
            | (SDitHP251.reduce32(res3) << 24);
    }

    static int add(int x, int y)
    {
        int z0 = SDitHP251.reduce16((x & 0xff) + (y & 0xff));
        int z1 = SDitHP251.reduce16(((x >>> 8) & 0xff) + ((y >>> 8) & 0xff));
        int z2 = SDitHP251.reduce16(((x >>> 16) & 0xff) + ((y >>> 16) & 0xff));
        int z3 = SDitHP251.reduce16(((x >>> 24) & 0xff) + ((y >>> 24) & 0xff));
        return z0 | (z1 << 8) | (z2 << 16) | (z3 << 24);
    }

    static int sub(int x, int y)
    {
        int z0 = SDitHP251.reduce16((x & 0xff) + 251 - (y & 0xff));
        int z1 = SDitHP251.reduce16(((x >>> 8) & 0xff) + 251 - ((y >>> 8) & 0xff));
        int z2 = SDitHP251.reduce16(((x >>> 16) & 0xff) + 251 - ((y >>> 16) & 0xff));
        int z3 = SDitHP251.reduce16(((x >>> 24) & 0xff) + 251 - ((y >>> 24) & 0xff));
        return z0 | (z1 << 8) | (z2 << 16) | (z3 << 24);
    }

    static int dlog(int x)
    {
        int lu = LOG16[x & 0xffff];
        int lv = LOG16[(x >>> 16) & 0xffff];
        if (lv == ORDER_P251P2)
        {
            return PP_POWER_P251P4 * lu;
        }
        int ldiff = (lu == ORDER_P251P2) ? ORDER_P251P2 : (lu >= lv ? lu - lv : ORDER_P251P2 + lu - lv);
        long sum = ((long)LOG1_32[ldiff] & 0xffffffffL) + (long)PP_POWER_P251P4 * (long)lv;
        return (int)(sum % ORDER_P251P4);
    }

    static int dexp(int x)
    {
        long xl = x & 0xffffffffL;
        if (xl == ORDER_P251P4)
        {
            return 0;
        }
        int lv = (int)(xl / PP_POWER_P251P4);
        int lu = (int)(xl % PP_POWER_P251P4);
        if (lu == 0)
        {
            return EXP16[lv] & 0xffff;
        }
        int ru = EXP1_32_U[lu] & 0xffff;
        int rv = EXP1_32_V[lu] & 0xffff;
        int lru = (ru == ORDER_P251P2) ? ORDER_P251P2 : (ru + lv) % ORDER_P251P2;
        int lrv = (rv == ORDER_P251P2) ? ORDER_P251P2 : (rv + lv) % ORDER_P251P2;
        return ((EXP16[lrv] & 0xffff) << 16) | (EXP16[lru] & 0xffff);
    }

    static int dlogPow(int logx, int p)
    {
        long order = ORDER_P251P4;
        if ((logx & 0xffffffffL) == order)
        {
            return (int)order;
        }
        long v = ((long)p & 0xffffffffL) * ((long)logx & 0xffffffffL);
        return (int)(v % order);
    }

    static int dlogMul(int logx, int logy)
    {
        long order = ORDER_P251P4;
        if ((logx & 0xffffffffL) == order || (logy & 0xffffffffL) == order)
        {
            return (int)order;
        }
        long l = ((long)logx & 0xffffffffL) + ((long)logy & 0xffffffffL);
        if (l >= order)
        {
            l -= order;
        }
        return (int)l;
    }

    static int mulTable(int x, int y)
    {
        return dexp(dlogMul(dlog(x), dlog(y)));
    }

    private static void initP251P2Tables()
    {
        EXP16[ORDER_P251P2] = 0;
        EXP16[0] = 1;
        EXP16[1] = GEN_P251P2;
        for (int i = 2; i < PP_POWER_P251P2; ++i)
        {
            EXP16[i] = (char)mulNaive16(EXP16[i - 1] & 0xffff, GEN_P251P2);
        }
        for (int i = 0; i < PP_POWER_P251P2; ++i)
        {
            int l = EXP16[i] & 0xffff;
            int l0 = SDitHP251.DLOG()[l & 0xff] & 0xff;
            int l1 = SDitHP251.DLOG()[(l >>> 8) & 0xff] & 0xff;
            for (int j = 1; j < SDitHP251.ORDER; ++j)
            {
                l0 = (l0 == SDitHP251.ORDER) ? SDitHP251.ORDER : (l0 == SDitHP251.ORDER - 1 ? 0 : l0 + 1);
                l1 = (l1 == SDitHP251.ORDER) ? SDitHP251.ORDER : (l1 == SDitHP251.ORDER - 1 ? 0 : l1 + 1);
                int e = (SDitHP251.DEXP()[l0] & 0xff) | ((SDitHP251.DEXP()[l1] & 0xff) << 8);
                EXP16[i + PP_POWER_P251P2 * j] = (char)e;
            }
        }
        for (int i = 0; i <= ORDER_P251P2; ++i)
        {
            LOG16[EXP16[i] & 0xffff] = (char)i;
        }
    }

    private static void initP251P4Tables()
    {
        int z = 1;
        EXP1_32_U[0] = 0;
        EXP1_32_V[0] = (char)ORDER_P251P2;
        for (int i = 1; i < PP_POWER_P251P4; ++i)
        {
            z = mulNaive(z, GEN_P251P4);
            int zlo = z & 0xffff;
            int zhi = (z >>> 16) & 0xffff;
            int lu = LOG16[zlo];
            int lv = LOG16[zhi];
            EXP1_32_U[i] = (char)lu;
            EXP1_32_V[i] = (char)lv;
            int ldiff = (lu == ORDER_P251P2) ? ORDER_P251P2 : (lu >= lv ? lu - lv : ORDER_P251P2 + lu - lv);
            long v = (lv == 0) ? i : (ORDER_P251P4 + i - (long)PP_POWER_P251P4 * lv);
            LOG1_32[ldiff] = (int)v;
        }
    }
}
