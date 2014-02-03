package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.crypto.util.Pack;

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

    public static int add(int[] x, int xOff, int[] y, int yOff, int[] z, int zOff)
    {
        long c = 0;
        c += (x[xOff + 0] & M) + (y[yOff + 0] & M);
        z[zOff + 0] = (int)c;
        c >>>= 32;
        c += (x[xOff + 1] & M) + (y[yOff + 1] & M);
        z[zOff + 1] = (int)c;
        c >>>= 32;
        c += (x[xOff + 2] & M) + (y[yOff + 2] & M);
        z[zOff + 2] = (int)c;
        c >>>= 32;
        c += (x[xOff + 3] & M) + (y[yOff + 3] & M);
        z[zOff + 3] = (int)c;
        c >>>= 32;
        c += (x[xOff + 4] & M) + (y[yOff + 4] & M);
        z[zOff + 4] = (int)c;
        c >>>= 32;
        c += (x[xOff + 5] & M) + (y[yOff + 5] & M);
        z[zOff + 5] = (int)c;
        c >>>= 32;
        c += (x[xOff + 6] & M) + (y[yOff + 6] & M);
        z[zOff + 6] = (int)c;
        c >>>= 32;
        c += (x[xOff + 7] & M) + (y[yOff + 7] & M);
        z[zOff + 7] = (int)c;
        c >>>= 32;
        return (int)c;
    }

    public static int addBothTo(int[] x, int[] y, int[] z)
    {
        long c = 0;
        c += (x[0] & M) + (y[0] & M) + (z[0] & M);
        z[0] = (int)c;
        c >>>= 32;
        c += (x[1] & M) + (y[1] & M) + (z[1] & M);
        z[1] = (int)c;
        c >>>= 32;
        c += (x[2] & M) + (y[2] & M) + (z[2] & M);
        z[2] = (int)c;
        c >>>= 32;
        c += (x[3] & M) + (y[3] & M) + (z[3] & M);
        z[3] = (int)c;
        c >>>= 32;
        c += (x[4] & M) + (y[4] & M) + (z[4] & M);
        z[4] = (int)c;
        c >>>= 32;
        c += (x[5] & M) + (y[5] & M) + (z[5] & M);
        z[5] = (int)c;
        c >>>= 32;
        c += (x[6] & M) + (y[6] & M) + (z[6] & M);
        z[6] = (int)c;
        c >>>= 32;
        c += (x[7] & M) + (y[7] & M) + (z[7] & M);
        z[7] = (int)c;
        c >>>= 32;
        return (int)c;
    }

    public static int addBothTo(int[] x, int xOff, int[] y, int yOff, int[] z, int zOff)
    {
        long c = 0;
        c += (x[xOff + 0] & M) + (y[yOff + 0] & M) + (z[zOff + 0] & M);
        z[zOff + 0] = (int)c;
        c >>>= 32;
        c += (x[xOff + 1] & M) + (y[yOff + 1] & M) + (z[zOff + 1] & M);
        z[zOff + 1] = (int)c;
        c >>>= 32;
        c += (x[xOff + 2] & M) + (y[yOff + 2] & M) + (z[zOff + 2] & M);
        z[zOff + 2] = (int)c;
        c >>>= 32;
        c += (x[xOff + 3] & M) + (y[yOff + 3] & M) + (z[zOff + 3] & M);
        z[zOff + 3] = (int)c;
        c >>>= 32;
        c += (x[xOff + 4] & M) + (y[yOff + 4] & M) + (z[zOff + 4] & M);
        z[zOff + 4] = (int)c;
        c >>>= 32;
        c += (x[xOff + 5] & M) + (y[yOff + 5] & M) + (z[zOff + 5] & M);
        z[zOff + 5] = (int)c;
        c >>>= 32;
        c += (x[xOff + 6] & M) + (y[yOff + 6] & M) + (z[zOff + 6] & M);
        z[zOff + 6] = (int)c;
        c >>>= 32;
        c += (x[xOff + 7] & M) + (y[yOff + 7] & M) + (z[zOff + 7] & M);
        z[zOff + 7] = (int)c;
        c >>>= 32;
        return (int)c;
    }

    // TODO Re-write to allow full range for x?
    public static int addDWord(long x, int[] z, int zOff)
    {
        // assert zOff <= 6;
        long c = x;
        c += (z[zOff + 0] & M);
        z[zOff + 0] = (int)c;
        c >>>= 32;
        c += (z[zOff + 1] & M);
        z[zOff + 1] = (int)c;
        c >>>= 32;
        return c == 0 ? 0 : inc(z, zOff + 2);
    }

    public static int addExt(int[] xx, int[] yy, int[] zz)
    {
        long c = 0;
        for (int i = 0; i < 16; ++i)
        {
            c += (xx[i] & M) + (yy[i] & M);
            zz[i] = (int)c;
            c >>>= 32;
        }
        return (int)c;
    }

    public static int addTo(int[] x, int xOff, int[] z, int zOff, int cIn)
    {
        long c = cIn & M;
        c += (x[xOff + 0] & M) + (z[zOff + 0] & M);
        z[zOff + 0] = (int)c;
        c >>>= 32;
        c += (x[xOff + 1] & M) + (z[zOff + 1] & M);
        z[zOff + 1] = (int)c;
        c >>>= 32;
        c += (x[xOff + 2] & M) + (z[zOff + 2] & M);
        z[zOff + 2] = (int)c;
        c >>>= 32;
        c += (x[xOff + 3] & M) + (z[zOff + 3] & M);
        z[zOff + 3] = (int)c;
        c >>>= 32;
        c += (x[xOff + 4] & M) + (z[zOff + 4] & M);
        z[zOff + 4] = (int)c;
        c >>>= 32;
        c += (x[xOff + 5] & M) + (z[zOff + 5] & M);
        z[zOff + 5] = (int)c;
        c >>>= 32;
        c += (x[xOff + 6] & M) + (z[zOff + 6] & M);
        z[zOff + 6] = (int)c;
        c >>>= 32;
        c += (x[xOff + 7] & M) + (z[zOff + 7] & M);
        z[zOff + 7] = (int)c;
        c >>>= 32;
        return (int)c;
    }

    public static int addToEachOther(int[] u, int uOff, int[] v, int vOff)
    {
        long c = 0;
        c += (u[uOff + 0] & M) + (v[vOff + 0] & M);
        u[uOff + 0] = (int)c;
        v[vOff + 0] = (int)c;
        c >>>= 32;
        c += (u[uOff + 1] & M) + (v[vOff + 1] & M);
        u[uOff + 1] = (int)c;
        v[vOff + 1] = (int)c;
        c >>>= 32;
        c += (u[uOff + 2] & M) + (v[vOff + 2] & M);
        u[uOff + 2] = (int)c;
        v[vOff + 2] = (int)c;
        c >>>= 32;
        c += (u[uOff + 3] & M) + (v[vOff + 3] & M);
        u[uOff + 3] = (int)c;
        v[vOff + 3] = (int)c;
        c >>>= 32;
        c += (u[uOff + 4] & M) + (v[vOff + 4] & M);
        u[uOff + 4] = (int)c;
        v[vOff + 4] = (int)c;
        c >>>= 32;
        c += (u[uOff + 5] & M) + (v[vOff + 5] & M);
        u[uOff + 5] = (int)c;
        v[vOff + 5] = (int)c;
        c >>>= 32;
        c += (u[uOff + 6] & M) + (v[vOff + 6] & M);
        u[uOff + 6] = (int)c;
        v[vOff + 6] = (int)c;
        c >>>= 32;
        c += (u[uOff + 7] & M) + (v[vOff + 7] & M);
        u[uOff + 7] = (int)c;
        v[vOff + 7] = (int)c;
        c >>>= 32;
        return (int)c;
    }

    public static int addWordExt(int x, int[] zz, int zzOff)
    {
        // assert zzOff <= 15;
        long c = (x & M) + (zz[zzOff + 0] & M);
        zz[zzOff + 0] = (int)c;
        c >>>= 32;
        return c == 0 ? 0 : incExt(zz, zzOff + 1);
    }

    public static int[] create()
    {
        return new int[8];
    }

    public static int[] createExt()
    {
        return new int[16];
    }

    public static int dec(int[] z, int zOff)
    {
        // assert zOff <= 8;
        for (int i = zOff; i < 8; ++i)
        {
            if (--z[i] != -1)
            {
                return 0;
            }
        }
        return -1;
    }

    public static boolean diff(int[] x, int xOff, int[] y, int yOff, int[] z, int zOff)
    {
        boolean pos = gte(x, xOff, y, yOff);
        if (pos)
        {
            sub(x, xOff, y, yOff, z, zOff);
        }
        else
        {
            sub(y, yOff, x, xOff, z, zOff);
        }
        return pos;
    }

    public static int[] fromBigInteger(BigInteger x)
    {
        if (x.signum() < 0 || x.bitLength() > 256)
        {
            throw new IllegalArgumentException();
        }

        int[] z = create();
        int i = 0;
        while (x.signum() != 0)
        {
            z[i++] = x.intValue();
            x = x.shiftRight(32);
        }
        return z;
    }

    public static int getBit(int[] x, int bit)
    {
        if (bit == 0)
        {
            return x[0] & 1;
        }
        if ((bit & 255) != bit)
        {
            return 0;
        }
        int w = bit >>> 5;
        int b = bit & 31;
        return (x[w] >>> b) & 1;
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
        return true;
    }

    public static boolean gte(int[] x, int xOff, int[] y, int yOff)
    {
        for (int i = 7; i >= 0; --i)
        {
            int x_i = x[xOff + i] ^ Integer.MIN_VALUE;
            int y_i = y[yOff + i] ^ Integer.MIN_VALUE;
            if (x_i < y_i)
                return false;
            if (x_i > y_i)
                return true;
        }
        return true;
    }

    public static boolean gteExt(int[] xx, int[] yy)
    {
        for (int i = 15; i >= 0; --i)
        {
            int xx_i = xx[i] ^ Integer.MIN_VALUE;
            int yy_i = yy[i] ^ Integer.MIN_VALUE;
            if (xx_i < yy_i)
                return false;
            if (xx_i > yy_i)
                return true;
        }
        return true;
    }

    public static int inc(int[] z, int zOff)
    {
        // assert zOff <= 8;
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
        // assert zzOff <= 16;
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
        for (int i = 0; i < 8; ++i)
        {
            if (x[i] != 0)
            {
                return false;
            }
        }
        return true;
    }

    public static boolean isZeroExt(int[] xx)
    {
        for (int i = 0; i < 16; ++i)
        {
            if (xx[i] != 0)
            {
                return false;
            }
        }
        return true;
    }

    public static void mul(int[] x, int[] y, int[] zz)
    {
        long y_0 = y[0] & M;
        long y_1 = y[1] & M;
        long y_2 = y[2] & M;
        long y_3 = y[3] & M;
        long y_4 = y[4] & M;
        long y_5 = y[5] & M;
        long y_6 = y[6] & M;
        long y_7 = y[7] & M;

        {
            long c = 0, x_0 = x[0] & M;
            c += x_0 * y_0;
            zz[0] = (int)c;
            c >>>= 32;
            c += x_0 * y_1;
            zz[1] = (int)c;
            c >>>= 32;
            c += x_0 * y_2;
            zz[2] = (int)c;
            c >>>= 32;
            c += x_0 * y_3;
            zz[3] = (int)c;
            c >>>= 32;
            c += x_0 * y_4;
            zz[4] = (int)c;
            c >>>= 32;
            c += x_0 * y_5;
            zz[5] = (int)c;
            c >>>= 32;
            c += x_0 * y_6;
            zz[6] = (int)c;
            c >>>= 32;
            c += x_0 * y_7;
            zz[7] = (int)c;
            c >>>= 32;
            zz[8] = (int)c;
        }

        for (int i = 1; i < 8; ++i)
        {
            long c = 0, x_i = x[i] & M;
            c += x_i * y_0 + (zz[i + 0] & M);
            zz[i + 0] = (int)c;
            c >>>= 32;
            c += x_i * y_1 + (zz[i + 1] & M);
            zz[i + 1] = (int)c;
            c >>>= 32;
            c += x_i * y_2 + (zz[i + 2] & M);
            zz[i + 2] = (int)c;
            c >>>= 32;
            c += x_i * y_3 + (zz[i + 3] & M);
            zz[i + 3] = (int)c;
            c >>>= 32;
            c += x_i * y_4 + (zz[i + 4] & M);
            zz[i + 4] = (int)c;
            c >>>= 32;
            c += x_i * y_5 + (zz[i + 5] & M);
            zz[i + 5] = (int)c;
            c >>>= 32;
            c += x_i * y_6 + (zz[i + 6] & M);
            zz[i + 6] = (int)c;
            c >>>= 32;
            c += x_i * y_7 + (zz[i + 7] & M);
            zz[i + 7] = (int)c;
            c >>>= 32;
            zz[i + 8] = (int)c;
        }
    }

    public static void mul(int[] x, int xOff, int[] y, int yOff, int[] zz, int zzOff)
    {
        long y_0 = y[yOff + 0] & M;
        long y_1 = y[yOff + 1] & M;
        long y_2 = y[yOff + 2] & M;
        long y_3 = y[yOff + 3] & M;
        long y_4 = y[yOff + 4] & M;
        long y_5 = y[yOff + 5] & M;
        long y_6 = y[yOff + 6] & M;
        long y_7 = y[yOff + 7] & M;

        {
            long c = 0, x_0 = x[xOff + 0] & M;
            c += x_0 * y_0;
            zz[zzOff + 0] = (int)c;
            c >>>= 32;
            c += x_0 * y_1;
            zz[zzOff + 1] = (int)c;
            c >>>= 32;
            c += x_0 * y_2;
            zz[zzOff + 2] = (int)c;
            c >>>= 32;
            c += x_0 * y_3;
            zz[zzOff + 3] = (int)c;
            c >>>= 32;
            c += x_0 * y_4;
            zz[zzOff + 4] = (int)c;
            c >>>= 32;
            c += x_0 * y_5;
            zz[zzOff + 5] = (int)c;
            c >>>= 32;
            c += x_0 * y_6;
            zz[zzOff + 6] = (int)c;
            c >>>= 32;
            c += x_0 * y_7;
            zz[zzOff + 7] = (int)c;
            c >>>= 32;
            zz[zzOff + 8] = (int)c;
        }

        for (int i = 1; i < 8; ++i)
        {
            ++zzOff;
            long c = 0, x_i = x[xOff + i] & M;
            c += x_i * y_0 + (zz[zzOff + 0] & M);
            zz[zzOff + 0] = (int)c;
            c >>>= 32;
            c += x_i * y_1 + (zz[zzOff + 1] & M);
            zz[zzOff + 1] = (int)c;
            c >>>= 32;
            c += x_i * y_2 + (zz[zzOff + 2] & M);
            zz[zzOff + 2] = (int)c;
            c >>>= 32;
            c += x_i * y_3 + (zz[zzOff + 3] & M);
            zz[zzOff + 3] = (int)c;
            c >>>= 32;
            c += x_i * y_4 + (zz[zzOff + 4] & M);
            zz[zzOff + 4] = (int)c;
            c >>>= 32;
            c += x_i * y_5 + (zz[zzOff + 5] & M);
            zz[zzOff + 5] = (int)c;
            c >>>= 32;
            c += x_i * y_6 + (zz[zzOff + 6] & M);
            zz[zzOff + 6] = (int)c;
            c >>>= 32;
            c += x_i * y_7 + (zz[zzOff + 7] & M);
            zz[zzOff + 7] = (int)c;
            c >>>= 32;
            zz[zzOff + 8] = (int)c;
        }
    }

    public static long mul33AddExt(int w, int[] xx, int xxOff, int[] yy, int yyOff, int[] zz, int zzOff)
    {
        // assert x >>> 31 == 0;
        // assert xxOff <= 8;
        // assert yyOff <= 8;
        // assert zzOff <= 8;

        long c = 0, wVal = w & M;
        long xx00 = xx[xxOff + 0] & M;
        c += wVal * xx00 + (yy[yyOff + 0] & M);
        zz[zzOff + 0] = (int)c;
        c >>>= 32;
        long xx01 = xx[xxOff + 1] & M;
        c += wVal * xx01 + xx00 + (yy[yyOff + 1] & M);
        zz[zzOff + 1] = (int)c;
        c >>>= 32;
        long xx02 = xx[xxOff + 2] & M;
        c += wVal * xx02 + xx01 + (yy[yyOff + 2] & M);
        zz[zzOff + 2] = (int)c;
        c >>>= 32;
        long xx03 = xx[xxOff + 3] & M;
        c += wVal * xx03 + xx02 + (yy[yyOff + 3] & M);
        zz[zzOff + 3] = (int)c;
        c >>>= 32;
        long xx04 = xx[xxOff + 4] & M;
        c += wVal * xx04 + xx03 + (yy[yyOff + 4] & M);
        zz[zzOff + 4] = (int)c;
        c >>>= 32;
        long xx05 = xx[xxOff + 5] & M;
        c += wVal * xx05 + xx04 + (yy[yyOff + 5] & M);
        zz[zzOff + 5] = (int)c;
        c >>>= 32;
        long xx06 = xx[xxOff + 6] & M;
        c += wVal * xx06 + xx05 + (yy[yyOff + 6] & M);
        zz[zzOff + 6] = (int)c;
        c >>>= 32;
        long xx07 = xx[xxOff + 7] & M;
        c += wVal * xx07 + xx06 + (yy[yyOff + 7] & M);
        zz[zzOff + 7] = (int)c;
        c >>>= 32;
        c += xx07;
        return c;
    }

    public static int mulWordAddExt(int x, int[] yy, int yyOff, int[] zz, int zzOff)
    {
        // assert yyOff <= 8;
        // assert zzOff <= 8;
        long c = 0, xVal = x & M;
        c += xVal * (yy[yyOff + 0] & M) + (zz[zzOff + 0] & M);
        zz[zzOff + 0] = (int)c;
        c >>>= 32;
        c += xVal * (yy[yyOff + 1] & M) + (zz[zzOff + 1] & M);
        zz[zzOff + 1] = (int)c;
        c >>>= 32;
        c += xVal * (yy[yyOff + 2] & M) + (zz[zzOff + 2] & M);
        zz[zzOff + 2] = (int)c;
        c >>>= 32;
        c += xVal * (yy[yyOff + 3] & M) + (zz[zzOff + 3] & M);
        zz[zzOff + 3] = (int)c;
        c >>>= 32;
        c += xVal * (yy[yyOff + 4] & M) + (zz[zzOff + 4] & M);
        zz[zzOff + 4] = (int)c;
        c >>>= 32;
        c += xVal * (yy[yyOff + 5] & M) + (zz[zzOff + 5] & M);
        zz[zzOff + 5] = (int)c;
        c >>>= 32;
        c += xVal * (yy[yyOff + 6] & M) + (zz[zzOff + 6] & M);
        zz[zzOff + 6] = (int)c;
        c >>>= 32;
        c += xVal * (yy[yyOff + 7] & M) + (zz[zzOff + 7] & M);
        zz[zzOff + 7] = (int)c;
        c >>>= 32;
        return (int)c;
    }

    public static int mul33DWordAdd(int x, long y, int[] z, int zOff)
    {
        // assert x >>> 31 == 0;
        // assert zOff <= 4;

        long c = 0, xVal = x & M;
        long y00 = y & M;
        c += xVal * y00 + (z[zOff + 0] & M);
        z[zOff + 0] = (int)c;
        c >>>= 32;
        long y01 = y >>> 32;
        c += xVal * y01 + y00 + (z[zOff + 1] & M);
        z[zOff + 1] = (int)c;
        c >>>= 32;
        c += y01 + (z[zOff + 2] & M);
        z[zOff + 2] = (int)c;
        c >>>= 32;
        c += (z[zOff + 3] & M);
        z[zOff + 3] = (int)c;
        c >>>= 32;
        return c == 0 ? 0 : inc(z, zOff + 4);
    }

    public static int mulWordDwordAdd(int x, long y, int[] z, int zOff)
    {
        // assert zOff <= 5;
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
        // assert zzOff <= 8;
        long c = 0, xVal = x & M;
        int i = 0;
        do
        {
            c += xVal * (y[i] & M);
            zz[zzOff + i] = (int)c;
            c >>>= 32;
        }
        while (++i < 8);
        return (int)c;
    }

    public static int shiftDownBit(int[] x, int xLen, int c)
    {
        int i = xLen;
        while (--i >= 0)
        {
            int next = x[i];
            x[i] = (next >>> 1) | (c << 31);
            c = next;
        }
        return c << 31;
    }

    public static int shiftDownBit(int[] x, int c, int[] z)
    {
        int i = 8;
        while (--i >= 0)
        {
            int next = x[i];
            z[i] = (next >>> 1) | (c << 31);
            c = next;
        }
        return c << 31;
    }

    public static int shiftDownBits(int[] x, int xLen, int bits, int c)
    {
//        assert bits > 0 && bits < 32;
        int i = xLen;
        while (--i >= 0)
        {
            int next = x[i];
            x[i] = (next >>> bits) | (c << -bits);
            c = next;
        }
        return c << -bits;
    }

    public static int shiftDownWord(int[] x, int xLen, int c)
    {
        int i = xLen;
        while (--i >= 0)
        {
            int next = x[i];
            x[i] = c;
            c = next;
        }
        return c;
    }

    public static int shiftUpBit(int[] x, int xLen, int c)
    {
        for (int i = 0; i < xLen; ++i)
        {
            int next = x[i];
            x[i] = (next << 1) | (c >>> 31);
            c = next;
        }
        return c >>> 31;
    }

    public static int shiftUpBit(int[] x, int xOff, int xLen, int c)
    {
        for (int i = 0; i < xLen; ++i)
        {
            int next = x[xOff + i];
            x[xOff + i] = (next << 1) | (c >>> 31);
            c = next;
        }
        return c >>> 31;
    }

    public static int shiftUpBit(int[] x, int c, int[] z)
    {
        for (int i = 0; i < 8; ++i)
        {
            int next = x[i];
            z[i] = (next << 1) | (c >>> 31);
            c = next;
        }
        return c >>> 31;
    }

    public static void square(int[] x, int[] zz)
    {
        long x_0 = x[0] & M;
        long zz_1;

        {
            int c = 0, i = 7, j = 16;
            do
            {
                long xVal = (x[i--] & M);
                long p = xVal * xVal;
                zz[--j] = (c << 31) | (int)(p >>> 33);
                zz[--j] = (int)(p >>> 1);
                c = (int)p;
            }
            while (i > 0);

            {
                long p = x_0 * x_0;
                zz_1 = ((c << 31) & M) | (p >>> 33);
                zz[0] = (int)(p >>> 1);
            }
        }

        long x_1 = x[1] & M;
        long zz_2 = zz[2] & M;

        {
            zz_1 += x_1 * x_0;
            zz[1] = (int)zz_1;
            zz_2 += zz_1 >>> 32;
        }

        long x_2 = x[2] & M;
        long zz_3 = zz[3] & M;
        long zz_4 = zz[4] & M;
        {
            zz_2 += x_2 * x_0;
            zz[2] = (int)zz_2;
            zz_3 += (zz_2 >>> 32) + x_2 * x_1;
            zz_4 += zz_3 >>> 32;
            zz_3 &= M;
        }

        long x_3 = x[3] & M;
        long zz_5 = zz[5] & M;
        long zz_6 = zz[6] & M;
        {
            zz_3 += x_3 * x_0;
            zz[3] = (int)zz_3;
            zz_4 += (zz_3 >>> 32) + x_3 * x_1;
            zz_5 += (zz_4 >>> 32) + x_3 * x_2;
            zz_4 &= M;
            zz_6 += zz_5 >>> 32;
            zz_5 &= M;
        }

        long x_4 = x[4] & M;
        long zz_7 = zz[7] & M;
        long zz_8 = zz[8] & M;
        {
            zz_4 += x_4 * x_0;
            zz[4] = (int)zz_4;
            zz_5 += (zz_4 >>> 32) + x_4 * x_1;
            zz_6 += (zz_5 >>> 32) + x_4 * x_2;
            zz_5 &= M;
            zz_7 += (zz_6 >>> 32) + x_4 * x_3;
            zz_6 &= M;
            zz_8 += zz_7 >>> 32;
            zz_7 &= M;
        }

        long x_5 = x[5] & M;
        long zz_9 = zz[9] & M;
        long zz_10 = zz[10] & M;
        {
            zz_5 += x_5 * x_0;
            zz[5] = (int)zz_5;
            zz_6 += (zz_5 >>> 32) + x_5 * x_1;
            zz_7 += (zz_6 >>> 32) + x_5 * x_2;
            zz_6 &= M;
            zz_8 += (zz_7 >>> 32) + x_5 * x_3;
            zz_7 &= M;
            zz_9 += (zz_8 >>> 32) + x_5 * x_4;
            zz_8 &= M;
            zz_10 += zz_9 >>> 32;
            zz_9 &= M;
        }

        long x_6 = x[6] & M;
        long zz_11 = zz[11] & M;
        long zz_12 = zz[12] & M;
        {
            zz_6 += x_6 * x_0;
            zz[6] = (int)zz_6;
            zz_7 += (zz_6 >>> 32) + x_6 * x_1;
            zz_8 += (zz_7 >>> 32) + x_6 * x_2;
            zz_7 &= M;
            zz_9 += (zz_8 >>> 32) + x_6 * x_3;
            zz_8 &= M;
            zz_10 += (zz_9 >>> 32) + x_6 * x_4;
            zz_9 &= M;
            zz_11 += (zz_10 >>> 32) + x_6 * x_5;
            zz_10 &= M;
            zz_12 += zz_11 >>> 32;
            zz_11 &= M;
        }

        long x_7 = x[7] & M;
        long zz_13 = zz[13] & M;
        long zz_14 = zz[14] & M;
        {
            zz_7 += x_7 * x_0;
            zz[7] = (int)zz_7;
            zz_8 += (zz_7 >>> 32) + x_7 * x_1;
            zz_9 += (zz_8 >>> 32) + x_7 * x_2;
            zz_10 += (zz_9 >>> 32) + x_7 * x_3;
            zz_11 += (zz_10 >>> 32) + x_7 * x_4;
            zz_12 += (zz_11 >>> 32) + x_7 * x_5;
            zz_13 += (zz_12 >>> 32) + x_7 * x_6;
            zz_14 += zz_13 >>> 32;
        }

        zz[8] = (int)zz_8;
        zz[9] = (int)zz_9;
        zz[10] = (int)zz_10;
        zz[11] = (int)zz_11;
        zz[12] = (int)zz_12;
        zz[13] = (int)zz_13;
        zz[14] = (int)zz_14;
        zz[15] += (int)(zz_14 >>> 32);

        shiftUpBit(zz, 16, (int)x_0 << 31);
    }

    public static void square(int[] x, int xOff, int[] zz, int zzOff)
    {
        long x_0 = x[xOff + 0] & M;
        long zz_1;

        {
            int c = 0, i = 7, j = 16;
            do
            {
                long xVal = (x[xOff + i--] & M);
                long p = xVal * xVal;
                zz[zzOff + --j] = (c << 31) | (int)(p >>> 33);
                zz[zzOff + --j] = (int)(p >>> 1);
                c = (int)p;
            }
            while (i > 0);

            {
                long p = x_0 * x_0;
                zz_1 = ((c << 31) & M) | (p >>> 33);
                zz[zzOff + 0] = (int)(p >>> 1);
            }
        }

        long x_1 = x[xOff + 1] & M;
        long zz_2 = zz[zzOff + 2] & M;

        {
            zz_1 += x_1 * x_0;
            zz[zzOff + 1] = (int)zz_1;
            zz_2 += zz_1 >>> 32;
        }

        long x_2 = x[xOff + 2] & M;
        long zz_3 = zz[zzOff + 3] & M;
        long zz_4 = zz[zzOff + 4] & M;
        {
            zz_2 += x_2 * x_0;
            zz[zzOff + 2] = (int)zz_2;
            zz_3 += (zz_2 >>> 32) + x_2 * x_1;
            zz_4 += zz_3 >>> 32;
            zz_3 &= M;
        }

        long x_3 = x[xOff + 3] & M;
        long zz_5 = zz[zzOff + 5] & M;
        long zz_6 = zz[zzOff + 6] & M;
        {
            zz_3 += x_3 * x_0;
            zz[zzOff + 3] = (int)zz_3;
            zz_4 += (zz_3 >>> 32) + x_3 * x_1;
            zz_5 += (zz_4 >>> 32) + x_3 * x_2;
            zz_4 &= M;
            zz_6 += zz_5 >>> 32;
            zz_5 &= M;
        }

        long x_4 = x[xOff + 4] & M;
        long zz_7 = zz[zzOff + 7] & M;
        long zz_8 = zz[zzOff + 8] & M;
        {
            zz_4 += x_4 * x_0;
            zz[zzOff + 4] = (int)zz_4;
            zz_5 += (zz_4 >>> 32) + x_4 * x_1;
            zz_6 += (zz_5 >>> 32) + x_4 * x_2;
            zz_5 &= M;
            zz_7 += (zz_6 >>> 32) + x_4 * x_3;
            zz_6 &= M;
            zz_8 += zz_7 >>> 32;
            zz_7 &= M;
        }

        long x_5 = x[xOff + 5] & M;
        long zz_9 = zz[zzOff + 9] & M;
        long zz_10 = zz[zzOff + 10] & M;
        {
            zz_5 += x_5 * x_0;
            zz[zzOff + 5] = (int)zz_5;
            zz_6 += (zz_5 >>> 32) + x_5 * x_1;
            zz_7 += (zz_6 >>> 32) + x_5 * x_2;
            zz_6 &= M;
            zz_8 += (zz_7 >>> 32) + x_5 * x_3;
            zz_7 &= M;
            zz_9 += (zz_8 >>> 32) + x_5 * x_4;
            zz_8 &= M;
            zz_10 += zz_9 >>> 32;
            zz_9 &= M;
        }

        long x_6 = x[xOff + 6] & M;
        long zz_11 = zz[zzOff + 11] & M;
        long zz_12 = zz[zzOff + 12] & M;
        {
            zz_6 += x_6 * x_0;
            zz[zzOff + 6] = (int)zz_6;
            zz_7 += (zz_6 >>> 32) + x_6 * x_1;
            zz_8 += (zz_7 >>> 32) + x_6 * x_2;
            zz_7 &= M;
            zz_9 += (zz_8 >>> 32) + x_6 * x_3;
            zz_8 &= M;
            zz_10 += (zz_9 >>> 32) + x_6 * x_4;
            zz_9 &= M;
            zz_11 += (zz_10 >>> 32) + x_6 * x_5;
            zz_10 &= M;
            zz_12 += zz_11 >>> 32;
            zz_11 &= M;
        }

        long x_7 = x[xOff + 7] & M;
        long zz_13 = zz[zzOff + 13] & M;
        long zz_14 = zz[zzOff + 14] & M;
        {
            zz_7 += x_7 * x_0;
            zz[zzOff + 7] = (int)zz_7;
            zz_8 += (zz_7 >>> 32) + x_7 * x_1;
            zz_9 += (zz_8 >>> 32) + x_7 * x_2;
            zz_10 += (zz_9 >>> 32) + x_7 * x_3;
            zz_11 += (zz_10 >>> 32) + x_7 * x_4;
            zz_12 += (zz_11 >>> 32) + x_7 * x_5;
            zz_13 += (zz_12 >>> 32) + x_7 * x_6;
            zz_14 += zz_13 >>> 32;
        }

        zz[zzOff + 8] = (int)zz_8;
        zz[zzOff + 9] = (int)zz_9;
        zz[zzOff + 10] = (int)zz_10;
        zz[zzOff + 11] = (int)zz_11;
        zz[zzOff + 12] = (int)zz_12;
        zz[zzOff + 13] = (int)zz_13;
        zz[zzOff + 14] = (int)zz_14;
        zz[zzOff + 15] += (int)(zz_14 >>> 32);

        shiftUpBit(zz, zzOff, 16, (int)x_0 << 31);
    }

    public static int squareWordAddExt(int[] x, int xPos, int[] zz)
    {
        // assert xPos > 0 && xPos < 8;
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

    public static int sub(int[] x, int xOff, int[] y, int yOff, int[] z, int zOff)
    {
        long c = 0;
        c += (x[xOff + 0] & M) - (y[yOff + 0] & M);
        z[zOff + 0] = (int)c;
        c >>= 32;
        c += (x[xOff + 1] & M) - (y[yOff + 1] & M);
        z[zOff + 1] = (int)c;
        c >>= 32;
        c += (x[xOff + 2] & M) - (y[yOff + 2] & M);
        z[zOff + 2] = (int)c;
        c >>= 32;
        c += (x[xOff + 3] & M) - (y[yOff + 3] & M);
        z[zOff + 3] = (int)c;
        c >>= 32;
        c += (x[xOff + 4] & M) - (y[yOff + 4] & M);
        z[zOff + 4] = (int)c;
        c >>= 32;
        c += (x[xOff + 5] & M) - (y[yOff + 5] & M);
        z[zOff + 5] = (int)c;
        c >>= 32;
        c += (x[xOff + 6] & M) - (y[yOff + 6] & M);
        z[zOff + 6] = (int)c;
        c >>= 32;
        c += (x[xOff + 7] & M) - (y[yOff + 7] & M);
        z[zOff + 7] = (int)c;
        c >>= 32;
        return (int)c;
    }

    public static int subBothFrom(int[] x, int[] y, int[] z)
    {
        long c = 0;
        c += (z[0] & M) - (x[0] & M) - (y[0] & M);
        z[0] = (int)c;
        c >>= 32;
        c += (z[1] & M) - (x[1] & M) - (y[1] & M);
        z[1] = (int)c;
        c >>= 32;
        c += (z[2] & M) - (x[2] & M) - (y[2] & M);
        z[2] = (int)c;
        c >>= 32;
        c += (z[3] & M) - (x[3] & M) - (y[3] & M);
        z[3] = (int)c;
        c >>= 32;
        c += (z[4] & M) - (x[4] & M) - (y[4] & M);
        z[4] = (int)c;
        c >>= 32;
        c += (z[5] & M) - (x[5] & M) - (y[5] & M);
        z[5] = (int)c;
        c >>= 32;
        c += (z[6] & M) - (x[6] & M) - (y[6] & M);
        z[6] = (int)c;
        c >>= 32;
        c += (z[7] & M) - (x[7] & M) - (y[7] & M);
        z[7] = (int)c;
        c >>= 32;
        return (int)c;
    }

    // TODO Re-write to allow full range for x?
    public static int subDWord(long x, int[] z)
    {
        long c = -x;
        c += (z[0] & M);
        z[0] = (int)c;
        c >>= 32;
        c += (z[1] & M);
        z[1] = (int)c;
        c >>= 32;
        return c == 0 ? 0 : dec(z, 2);
    }

    public static int subExt(int[] xx, int[] yy, int[] zz)
    {
        long c = 0;
        for (int i = 0; i < 16; ++i)
        {
            c += (xx[i] & M) - (yy[i] & M);
            zz[i] = (int)c;
            c >>= 32;
        }
        return (int)c;
    }

    public static int subFromExt(int[] x, int xOff, int[] zz, int zzOff)
    {
        // assert zzOff <= 8;
        long c = 0;
        c += (zz[zzOff + 0] & M) - (x[xOff + 0] & M);
        zz[zzOff + 0] = (int)c;
        c >>= 32;
        c += (zz[zzOff + 1] & M) - (x[xOff + 1] & M);
        zz[zzOff + 1] = (int)c;
        c >>= 32;
        c += (zz[zzOff + 2] & M) - (x[xOff + 2] & M);
        zz[zzOff + 2] = (int)c;
        c >>= 32;
        c += (zz[zzOff + 3] & M) - (x[xOff + 3] & M);
        zz[zzOff + 3] = (int)c;
        c >>= 32;
        c += (zz[zzOff + 4] & M) - (x[xOff + 4] & M);
        zz[zzOff + 4] = (int)c;
        c >>= 32;
        c += (zz[zzOff + 5] & M) - (x[xOff + 5] & M);
        zz[zzOff + 5] = (int)c;
        c >>= 32;
        c += (zz[zzOff + 6] & M) - (x[xOff + 6] & M);
        zz[zzOff + 6] = (int)c;
        c >>= 32;
        c += (zz[zzOff + 7] & M) - (x[xOff + 7] & M);
        zz[zzOff + 7] = (int)c;
        c >>= 32;
        return (int)c;
    }

    public static BigInteger toBigInteger(int[] x)
    {
        byte[] bs = new byte[32];
        for (int i = 0; i < 8; ++i)
        {
            int x_i = x[i];
            if (x_i != 0)
            {
                Pack.intToBigEndian(x_i, bs, (7 - i) << 2);
            }
        }
        return new BigInteger(1, bs);
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
