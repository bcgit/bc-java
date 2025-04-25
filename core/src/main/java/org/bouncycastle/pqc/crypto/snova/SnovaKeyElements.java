package org.bouncycastle.pqc.crypto.snova;

class SnovaKeyElements
{
    public final MapGroup1 map1;
    public final byte[][][] T12;     // [v][o]
    public final MapGroup2 map2;

    public SnovaKeyElements(SnovaParameters params)
    {
        int o = params.getO();
        int v = params.getV();
        int lsq = params.getLsq();
        map1 = new MapGroup1(params);
        T12 = new byte[v][o][lsq];
        map2 = new MapGroup2(params);
    }

    static int copy3d(byte[][][] alpha, byte[] output, int outOff)
    {
        for (int i = 0; i < alpha.length; ++i)
        {
            for (int j = 0; j < alpha[i].length; ++j)
            {
                System.arraycopy(alpha[i][j], 0, output, outOff, alpha[i][j].length);
                outOff += alpha[i][j].length;
            }
        }
        return outOff;
    }

    static int copy4d(byte[][][][] alpha, byte[] output, int outOff)
    {
        for (int i = 0; i < alpha.length; ++i)
        {
            outOff = copy3d(alpha[i], output, outOff);
        }
        return outOff;
    }

    static int copy3d(byte[] input, int inOff, byte[][][] alpha)
    {
        for (int i = 0; i < alpha.length; ++i)
        {
            for (int j = 0; j < alpha[i].length; ++j)
            {
                System.arraycopy(input, inOff, alpha[i][j], 0, alpha[i][j].length);
                inOff += alpha[i][j].length;
            }
        }
        return inOff;
    }

    static int copy4d(byte[] input, int inOff, byte[][][][] alpha)
    {
        for (int i = 0; i < alpha.length; ++i)
        {
            for (int j = 0; j < alpha[i].length; ++j)
            {
                for (int k = 0; k < alpha[i][j].length; ++k)
                {
                    System.arraycopy(input, inOff, alpha[i][j][k], 0, alpha[i][j][k].length);
                    inOff += alpha[i][j][k].length;
                }
            }
        }
        return inOff;
    }
}
