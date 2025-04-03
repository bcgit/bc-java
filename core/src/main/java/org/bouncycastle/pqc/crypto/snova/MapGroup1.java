package org.bouncycastle.pqc.crypto.snova;

import org.bouncycastle.util.GF16;

class MapGroup1
{
    public final byte[][][][] p11;  // [m][v][v]
    public final byte[][][][] p12;  // [m][v][o]
    public final byte[][][][] p21;  // [m][o][v]
    public final byte[][][] aAlpha; // [m][alpha]
    public final byte[][][] bAlpha; // [m][alpha]
    public final byte[][][] qAlpha1;// [m][alpha]
    public final byte[][][] qAlpha2;// [m][alpha]

    public MapGroup1(SnovaParameters params)
    {
        int m = params.getM();
        int v = params.getV();
        int o = params.getO();
        int alpha = params.getAlpha();
        int lsq = params.getLsq();
        p11 = new byte[m][v][v][lsq];
        p12 = new byte[m][v][o][lsq];
        p21 = new byte[m][o][v][lsq];
        aAlpha = new byte[m][alpha][lsq];
        bAlpha = new byte[m][alpha][lsq];
        qAlpha1 = new byte[m][alpha][lsq];
        qAlpha2 = new byte[m][alpha][lsq];
    }

    void decode(byte[] input, int len, boolean isl4or5)
    {
        //TODO: when (lsq & 1) == 1
        int inOff = decodeP(input, 0, p11, len);
        inOff += decodeP(input, inOff, p12, len - inOff);
        inOff += decodeP(input, inOff, p21, len - inOff);
        if (isl4or5)
        {
            inOff += decodeAlpha(input, inOff, aAlpha, len - inOff);
            inOff += decodeAlpha(input, inOff, bAlpha, len - inOff);
            inOff += decodeAlpha(input, inOff, qAlpha1, len - inOff);
            decodeAlpha(input, inOff, qAlpha2, len - inOff);
        }
    }

    static int decodeP(byte[] input, int inOff, byte[][][][] p, int len)
    {
        int rlt = 0;
        for (int i = 0; i < p.length; ++i)
        {
            rlt += decodeAlpha(input, inOff + rlt, p[i], len);
        }
        return rlt;
    }

    private static int decodeAlpha(byte[] input, int inOff, byte[][][] alpha, int len)
    {
        int rlt = 0;
        for (int i = 0; i < alpha.length; ++i)
        {
            rlt += decodeArray(input, inOff + rlt, alpha[i], len - rlt);
        }
        return rlt;
    }

    static int decodeArray(byte[] input, int inOff, byte[][] array, int len)
    {
        int rlt = 0;
        for (int j = 0; j < array.length; ++j)
        {
            int tmp = Math.min(array[j].length, len << 1);
            GF16.decode(input, inOff + rlt, array[j], 0, tmp);
            tmp = (tmp + 1) >> 1;
            rlt += tmp;
            len -= tmp;
        }
        return rlt;
    }

    void fill(byte[] input, boolean isl4or5)
    {
        int inOff = fillP(input, 0, p11, input.length);
        inOff += fillP(input, inOff, p12, input.length - inOff);
        inOff += fillP(input, inOff, p21, input.length - inOff);
        if (isl4or5)
        {
            inOff += fillAlpha(input, inOff, aAlpha, input.length - inOff);
            inOff += fillAlpha(input, inOff, bAlpha, input.length - inOff);
            inOff += fillAlpha(input, inOff, qAlpha1, input.length - inOff);
            fillAlpha(input, inOff, qAlpha2, input.length - inOff);
        }
    }

    static int fillP(byte[] input, int inOff, byte[][][][] p, int len)
    {
        int rlt = 0;
        for (int i = 0; i < p.length; ++i)
        {
            rlt += fillAlpha(input, inOff + rlt, p[i], len - rlt);
        }
        return rlt;
    }

    static int fillAlpha(byte[] input, int inOff, byte[][][] alpha, int len)
    {
        int rlt = 0;
        for (int i = 0; i < alpha.length; ++i)
        {
            for (int j = 0; j < alpha[i].length; ++j)
            {
                int tmp = Math.min(alpha[i][j].length, len - rlt);
                System.arraycopy(input, inOff + rlt, alpha[i][j], 0, tmp);
                rlt += tmp;
            }
        }
        return rlt;
    }
}
