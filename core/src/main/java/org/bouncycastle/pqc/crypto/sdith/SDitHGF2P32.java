package org.bouncycastle.pqc.crypto.sdith;

import org.bouncycastle.math.raw.GF256AES;

/**
 * GF(2^32) arithmetic helpers for SDitH, port of the reference gf2p32.c.
 * <p>
 * Tower-field construction:
 * <ul>
 *   <li>GF(2^16) = GF(256)[X] / (X^2 + X + 0x20), generator 0x118a.</li>
 *   <li>GF(2^32) = GF(2^16)[Y] / (Y^2 + Y + 0x2000), generator 0x8d1f8c20.</li>
 * </ul>
 * Multiplication is performed via log/exp tables (non-constant-time) for
 * compatibility with the reference; constant-time naive multiplication is also
 * provided for verification. The tables are lazily initialised.
 */
final class SDitHGF2P32
{
    static final int GEN_GF2P16 = 0x118a;
    static final int GEN_GF2P32 = 0x8d1f8c20;
    static final int IRRED_CST_GF2P16 = 0x20;
    static final int IRRED_CST_GF2P32 = 0x2000;

    private static final char[] LOG16 = new char[65536];
    private static final char[] EXP16 = new char[65536];
    private static final int[] LOG1_32 = new int[65536];
    private static final char[] EXP1_32_U = new char[65537];
    private static final char[] EXP1_32_V = new char[65537];

    static
    {
        initGF2P16Tables();
        initGF2P32Tables();
    }

    private SDitHGF2P32()
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
        int a0 = GF256AES.mul(xx0, yy0);
        int a1 = GF256AES.mul(xx0, yy1) ^ GF256AES.mul(xx1, yy0);
        int a2 = GF256AES.mul(xx1, yy1);
        a1 ^= a2;
        a0 ^= GF256AES.mul(IRRED_CST_GF2P16, a2);
        return ((a1 & 0xff) << 8) | (a0 & 0xff);
    }

    static int mulNaive(int x, int y)
    {
        int xx0 = x & 0xffff;
        int xx1 = (x >>> 16) & 0xffff;
        int yy0 = y & 0xffff;
        int yy1 = (y >>> 16) & 0xffff;
        int a0 = mulNaive16(xx0, yy0);
        int a1 = mulNaive16(xx0, yy1) ^ mulNaive16(xx1, yy0);
        int a2 = mulNaive16(xx1, yy1);
        a1 ^= a2;
        a0 ^= mulNaive16(IRRED_CST_GF2P32, a2);
        return (a1 << 16) | (a0 & 0xffff);
    }

    static int dlog(int x)
    {
        int lu = LOG16[x & 0xffff];
        int lv = LOG16[(x >>> 16) & 0xffff];
        if (lv == 0xffff)
        {
            return 0x10001 * lu;
        }
        int ldiff = (lu == 0xffff) ? 0xffff : (lu >= lv ? lu - lv : 0xffff + lu - lv);
        long v = ((long)LOG1_32[ldiff] & 0xffffffffL) + 0x10001L * lv;
        return (int)(v % 0xffffffffL);
    }

    static int dexp(int x)
    {
        long xl = x & 0xffffffffL;
        if (xl == 0xffffffffL)
        {
            return 0;
        }
        int lv = (int)(xl / 0x10001L);
        int lu = (int)(xl % 0x10001L);
        if (lu == 0)
        {
            return EXP16[lv] & 0xffff;
        }
        int ru = EXP1_32_U[lu] & 0xffff;
        int rv = EXP1_32_V[lu] & 0xffff;
        int lru = (ru == 0xffff) ? 0xffff : (ru + lv) % 0xffff;
        int lrv = (rv == 0xffff) ? 0xffff : (rv + lv) % 0xffff;
        return ((EXP16[lrv] & 0xffff) << 16) | (EXP16[lru] & 0xffff);
    }

    static int dlogPow(int logx, int p)
    {
        if (logx == 0xffffffff)
        {
            return 0xffffffff;
        }
        long v = ((long)p & 0xffffffffL) * ((long)logx & 0xffffffffL);
        return (int)(v % 0xffffffffL);
    }

    static int dlogMul(int logx, int logy)
    {
        if (logx == 0xffffffff || logy == 0xffffffff)
        {
            return 0xffffffff;
        }
        long order = 0xffffffffL;
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

    private static void initGF2P16Tables()
    {
        EXP16[0xffff] = 0;
        EXP16[0] = 1;
        EXP16[1] = GEN_GF2P16;
        for (int i = 2; i < 0x101; ++i)
        {
            EXP16[i] = (char)mulNaive16(EXP16[i - 1] & 0xffff, GEN_GF2P16);
        }
        for (int i = 0; i < 0x101; ++i)
        {
            int l = EXP16[i] & 0xffff;
            int l0 = SDitHGF256.dlog(l & 0xff);
            int l1 = SDitHGF256.dlog((l >>> 8) & 0xff);
            for (int j = 1; j < 255; ++j)
            {
                l0 = (l0 == 255) ? 255 : (l0 == 254 ? 0 : l0 + 1);
                l1 = (l1 == 255) ? 255 : (l1 == 254 ? 0 : l1 + 1);
                int e = (SDitHGF256.dexp(l0) & 0xff) | ((SDitHGF256.dexp(l1) & 0xff) << 8);
                EXP16[i + 0x101 * j] = (char)e;
            }
        }
        for (int i = 0; i < 65536; ++i)
        {
            LOG16[EXP16[i]] = (char)i;
        }
    }

    private static void initGF2P32Tables()
    {
        int z = 1;
        EXP1_32_U[0] = 0;
        EXP1_32_V[0] = (char)0xffff;
        for (int i = 1; i < 0x10001; ++i)
        {
            z = mulNaive(z, GEN_GF2P32);
            int zlo = z & 0xffff;
            int zhi = (z >>> 16) & 0xffff;
            int lu = LOG16[zlo];
            int lv = LOG16[zhi];
            EXP1_32_U[i] = (char)lu;
            EXP1_32_V[i] = (char)lv;
            int ldiff = (lu == 0xffff) ? 0xffff : (lu >= lv ? lu - lv : 0xffff + lu - lv);
            long v = (lv == 0) ? i : (0xffffffffL + i - 0x10001L * lv);
            LOG1_32[ldiff] = (int)v;
        }
    }
}
