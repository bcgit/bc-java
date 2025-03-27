package org.bouncycastle.pqc.crypto.snova;

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
        int lsq = params.getL() * params.getL();
        p11 = new byte[m][v][v][lsq];
        p12 = new byte[m][v][o][lsq];
        p21 = new byte[m][o][v][lsq];
        aAlpha = new byte[m][alpha][lsq];
        bAlpha = new byte[m][alpha][lsq];
        qAlpha1 = new byte[m][alpha][lsq];
        qAlpha2 = new byte[m][alpha][lsq];
    }

    public void fill(byte[] input)
    {
        int inOff = fillP(input, 0, p11, input.length);
        inOff += fillP(input, inOff, p12, input.length - inOff);
        inOff += fillP(input, inOff, p21, input.length - inOff);
        inOff += fillAlpha(input, inOff, aAlpha, input.length - inOff);
        inOff += fillAlpha(input, inOff, bAlpha, input.length - inOff);
        inOff += fillAlpha(input, inOff, qAlpha1, input.length - inOff);
        fillAlpha(input, inOff, qAlpha2, input.length - inOff);
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

    static void copyTo(byte[][][][] alpha, byte[] output)
    {
        int outOff = 0;
        for (int i = 0; i < alpha.length; ++i)
        {
            for (int j = 0; j < alpha[i].length; ++j)
            {
                for (int k = 0; k < alpha[i][j].length; ++k)
                {
                    System.arraycopy(alpha[i][j][k], 0, output, outOff, alpha[i][j][k].length);
                    outOff += alpha[i][j][k].length;
                }
            }
        }
    }
}
