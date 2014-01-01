package org.bouncycastle.math.ec.custom.sec;

public abstract class Nat256
{
    private static final long M = 0xFFFFFFFFL;

    public static int add(int[] x, int[] y, int[] z)
    {
        long c = 0;
        c += (x[0] & M) + (y[0] & M);
        z[0] = (int)c;
        c >>>= 32;
        c += (x[1] & M) + (y[1] & M);
        z[1] = (int)c;
        c >>>= 32;
        c += (x[2] & M) + (y[2] & M);
        z[2] = (int)c;
        c >>>= 32;
        c += (x[3] & M) + (y[3] & M);
        z[3] = (int)c;
        c >>>= 32;
        c += (x[4] & M) + (y[4] & M);
        z[4] = (int)c;
        c >>>= 32;
        c += (x[5] & M) + (y[5] & M);
        z[5] = (int)c;
        c >>>= 32;
        c += (x[6] & M) + (y[6] & M);
        z[6] = (int)c;
        c >>>= 32;
        c += (x[7] & M) + (y[7] & M);
        z[7] = (int)c;
        c >>>= 32;
        return (int)c;
    }

    public static int addDWord(long x, int[] z, int zOff)
    {
        assert zOff < 6;
        long c = x;
        c += (z[zOff + 0] & M);
        z[zOff + 0] = (int)c;
        c >>>= 32;
        c += (z[zOff + 1] & M);
        z[zOff + 1] = (int)c;
        c >>>= 32;
        return c == 0 ? 0 : inc(z, zOff + 2);
    }

    public static int addExt(int[] x, int xOff, int[] zz, int zzOff)
    {
        assert zzOff <= 8;
        long c = 0;
        c += (x[xOff + 0] & M) + (zz[zzOff + 0] & M);
        zz[zzOff + 0] = (int)c;
        c >>>= 32;
        c += (x[xOff + 1] & M) + (zz[zzOff + 1] & M);
        zz[zzOff + 1] = (int)c;
        c >>>= 32;
        c += (x[xOff + 2] & M) + (zz[zzOff + 2] & M);
        zz[zzOff + 2] = (int)c;
        c >>>= 32;
        c += (x[xOff + 3] & M) + (zz[zzOff + 3] & M);
        zz[zzOff + 3] = (int)c;
        c >>>= 32;
        c += (x[xOff + 4] & M) + (zz[zzOff + 4] & M);
        zz[zzOff + 4] = (int)c;
        c >>>= 32;
        c += (x[xOff + 5] & M) + (zz[zzOff + 5] & M);
        zz[zzOff + 5] = (int)c;
        c >>>= 32;
        c += (x[xOff + 6] & M) + (zz[zzOff + 6] & M);
        zz[zzOff + 6] = (int)c;
        c >>>= 32;
        c += (x[xOff + 7] & M) + (zz[zzOff + 7] & M);
        zz[zzOff + 7] = (int)c;
        c >>>= 32;
        return (int)c;
    }

    public static int addWordExt(int x, int[] zz, int zzOff)
    {
        assert zzOff < 15;
        long c = (x & M) + (zz[zzOff + 0] & M);
        zz[zzOff + 0] = (int)c;
        c >>>= 32;
        return c == 0 ? 0 : incExt(zz, zzOff + 1);
    }

    public static int dec(int[] z, int zOff)
    {
        assert zOff < 8;
        int i = zOff;
        do
        {
            if (--z[i] != -1)
            {
                return 0;
            }
        }
        while(++i < 8);
        return -1;
    }

    public static boolean gte(int[] x, int[] y)
    {
        for (int i = 7; i >= 0; --i)
        {
            int x_i = x[i] ^ Integer.MIN_VALUE;
            int y_i = y[i] ^ Integer.MIN_VALUE;
            if (x_i < y_i)
                return false;
            if (x_i > y_i)
                return true;
        }
        return false;
    }

    public static int inc(int[] z, int zOff)
    {
        assert zOff < 8;
        for (int i = zOff; i < 8; ++i)
        {
            if (++z[i] != 0)
            {
                return 0;
            }
        }
        return 1;
    }

    public static int incExt(int[] zz, int zzOff)
    {
        assert zzOff < 16;
        for (int i = zzOff; i < 16; ++i)
        {
            if (++zz[i] != 0)
            {
                return 0;
            }
        }
        return 1;
    }

    public static boolean isOne(int[] x)
    {
        if (x[0] != 1)
        {
            return false;
        }
        for (int i = 1; i < 8; ++i)
        {
            if (x[i] != 0)
            {
                return false;
            }
        }
        return true;
    }

    public static boolean isZero(int[] x)
    {
        if (x[0] != 0)
        {
            return false;
        }
        for (int i = 1; i < 8; ++i)
        {
            if (x[i] != 0)
            {
                return false;
            }
        }
        return true;
    }

    public static void mul(int[] x, int[] y, int[] zz)
    {
        zz[8] = mulWordExt(x[0], y, zz, 0);
        for (int i = 1; i < 8; ++i)
        {
            zz[i + 8] = mulWordAddExt(x[i], y, 0, zz, i);
        }
    }

    public static void mulAdd(int[] x, int[] y, int[] zz)
    {
        for (int i = 0; i < 8; ++i)
        {
            zz[i + 8] += mulWordAddExt(x[i], y, 0, zz, i);
        }
    }

    public static int mulWordAddExt(int x, int[] yy, int yyOff, int[] zz, int zzOff)
    {
        assert yyOff <= 8;
        assert zzOff <= 8;
        long c = 0, xVal = x & M;
        int i = 0;
        do
        {
            c += xVal * (yy[yyOff + i] & M) + (zz[zzOff + i] & M);
            zz[zzOff + i] = (int)c;
            c >>>= 32;
        }
        while (++i < 8);
//        c += xVal * (yy[yyOff + 0] & M) + (zz[zzOff + 0] & M);
//        zz[zzOff + 0] = (int)c;
//        c >>>= 32;
//        c += xVal * (yy[yyOff + 1] & M) + (zz[zzOff + 1] & M);
//        zz[zzOff + 1] = (int)c;
//        c >>>= 32;
//        c += xVal * (yy[yyOff + 2] & M) + (zz[zzOff + 2] & M);
//        zz[zzOff + 2] = (int)c;
//        c >>>= 32;
//        c += xVal * (yy[yyOff + 3] & M) + (zz[zzOff + 3] & M);
//        zz[zzOff + 3] = (int)c;
//        c >>>= 32;
//        c += xVal * (yy[yyOff + 4] & M) + (zz[zzOff + 4] & M);
//        zz[zzOff + 4] = (int)c;
//        c >>>= 32;
//        c += xVal * (yy[yyOff + 5] & M) + (zz[zzOff + 5] & M);
//        zz[zzOff + 5] = (int)c;
//        c >>>= 32;
//        c += xVal * (yy[yyOff + 6] & M) + (zz[zzOff + 6] & M);
//        zz[zzOff + 6] = (int)c;
//        c >>>= 32;
//        c += xVal * (yy[yyOff + 7] & M) + (zz[zzOff + 7] & M);
//        zz[zzOff + 7] = (int)c;
//        c >>>= 32;
        return (int)c;
    }

    public static int squareWordAddExt(int[] x, int xPos, int[] zz)
    {
        assert xPos > 0 && xPos < 8;
        long c = 0, xVal = x[xPos] & M;
        int i = 0;
        do
        {
            c += xVal * (x[i] & M) + (zz[xPos + i] & M);
            zz[xPos + i] = (int)c;
            c >>>= 32;
        }
        while (++i < xPos);
        return (int)c;
    }

    public static int mulWordDwordAdd(int x, long y, int[] z, int zOff)
    {
        assert zOff < 5;
        long c = 0, xVal = x & M;
        c += xVal * (y & M) + (z[zOff + 0] & M);
        z[zOff + 0] = (int)c;
        c >>>= 32;
        c += xVal * (y >>> 32) + (z[zOff + 1] & M);
        z[zOff + 1] = (int)c;
        c >>>= 32;
        c += (z[zOff + 2] & M);
        z[zOff + 2] = (int)c;
        c >>>= 32;
        return c == 0 ? 0 : inc(z, zOff + 3);
    }

    public static int mulWordExt(int x, int[] y, int[] zz, int zzOff)
    {
        assert zzOff <= 8;
        long c = 0, xVal = x & M;
        int i = 0;
        do
        {
            c += xVal * (y[i] & M);
            zz[zzOff + i] = (int)c;
            c >>>= 32;
        }
        while (++i < 8);
//        c += xVal * (y[0] & M);
//        zz[zzOff + 0] = (int)c;
//        c >>>= 32;
//        c += xVal * (y[1] & M);
//        zz[zzOff + 1] = (int)c;
//        c >>>= 32;
//        c += xVal * (y[2] & M);
//        zz[zzOff + 2] = (int)c;
//        c >>>= 32;
//        c += xVal * (y[3] & M);
//        zz[zzOff + 3] = (int)c;
//        c >>>= 32;
//        c += xVal * (y[4] & M);
//        zz[zzOff + 4] = (int)c;
//        c >>>= 32;
//        c += xVal * (y[5] & M);
//        zz[zzOff + 5] = (int)c;
//        c >>>= 32;
//        c += xVal * (y[6] & M);
//        zz[zzOff + 6] = (int)c;
//        c >>>= 32;
//        c += xVal * (y[7] & M);
//        zz[zzOff + 7] = (int)c;
//        c >>>= 32;
        return (int)c;
    }

    public static int shiftUp(int[] x, int xLen)
    {
        int prev = 0;
        for (int i = 0; i < xLen; ++i)
        {
            int next = x[i];
            x[i] = (next << 1) | prev;
            prev = next >>> 31;
        }
        return prev;
    }

    public static void square(int[] x, int[] zz)
    {
        int c = 0;
        int j = 8, k = 16;
        do
        {
            long xVal = (x[--j] & M);
            long p = xVal * xVal;
            zz[--k] = (c << 31) | (int)(p >>> 33);
            zz[--k] = (int)(p >>> 1);
            c = (int)p;
        }
        while (j > 0);

        for (int i = 1; i < 8; ++i)
        {
            c = squareWordAddExt(x, i, zz);
            addWordExt(c, zz, i << 1);
        }

        shiftUp(zz, 16);
        zz[0] |= x[0] & 1;
    }

    public static int sub(int[] x, int[] y, int[] z)
    {
        long c = 0;
        c += (x[0] & M) - (y[0] & M);
        z[0] = (int)c;
        c >>= 32;
        c += (x[1] & M) - (y[1] & M);
        z[1] = (int)c;
        c >>= 32;
        c += (x[2] & M) - (y[2] & M);
        z[2] = (int)c;
        c >>= 32;
        c += (x[3] & M) - (y[3] & M);
        z[3] = (int)c;
        c >>= 32;
        c += (x[4] & M) - (y[4] & M);
        z[4] = (int)c;
        c >>= 32;
        c += (x[5] & M) - (y[5] & M);
        z[5] = (int)c;
        c >>= 32;
        c += (x[6] & M) - (y[6] & M);
        z[6] = (int)c;
        c >>= 32;
        c += (x[7] & M) - (y[7] & M);
        z[7] = (int)c;
        c >>= 32;
        return (int)c;
    }

    public static int subDWord(long x, int[] z)
    {
        x = -x;
        x += (z[0] & M);
        z[0] = (int)x;
        x >>= 32;
        x += (z[1] & M);
        z[1] = (int)x;
        x >>= 32;
        return x == 0 ? 0 : dec(z, 2);
    }

    public static void zero(int[] z)
    {
        z[0] = 0;
        z[1] = 0;
        z[2] = 0;
        z[3] = 0;
        z[4] = 0;
        z[5] = 0;
        z[6] = 0;
        z[7] = 0;
    }
}
