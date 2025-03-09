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

        p11 = new byte[m][v][v][16];
        p12 = new byte[m][v][o][16];
        p21 = new byte[m][o][v][16];
        aAlpha = new byte[m][alpha][16];
        bAlpha = new byte[m][alpha][16];
        qAlpha1 = new byte[m][alpha][16];
        qAlpha2 = new byte[m][alpha][16];
    }

    public int decode(byte[] input, int len)
    {
        int inOff = decodeP(input, 0, p11, len);
        inOff += decodeP(input, inOff, p12, len - inOff);
        inOff += decodeP(input, inOff, p21, len - inOff);
        inOff += decodeAlpha(input, inOff, aAlpha, len - inOff);
        inOff += decodeAlpha(input, inOff, bAlpha, len - inOff);
        inOff += decodeAlpha(input, inOff, qAlpha1, len - inOff);
        inOff += decodeAlpha(input, inOff, qAlpha2, len - inOff);
        return inOff;
    }

    private int decodeP(byte[] input, int inOff, byte[][][][] p, int len)
    {
        int rlt = 0;
        for (int i = 0; i < p.length; ++i)
        {
            rlt += decodeAlpha(input, inOff + rlt, p[i], len);
        }
        return rlt;
    }

    private int decodeAlpha(byte[] input, int inOff, byte[][][] alpha, int len)
    {
        int rlt = 0;
        for (int i = 0; i < alpha.length; ++i)
        {
            for (int j = 0; j < alpha[i].length; ++j)
            {
                int tmp = Math.min(alpha[i][j].length, len << 1);
                GF16Utils.decode(input, inOff + rlt, alpha[i][j], 0, tmp);
                rlt += (tmp + 1) >> 1;
                len -= (tmp + 1) >> 1;
            }
        }
        return rlt;
    }

}
