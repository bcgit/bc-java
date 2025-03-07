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

    public int decode(byte[] input)
    {
        int inOff = decodeP(input, 0, p11);
        inOff = decodeP(input, inOff, p12);
        inOff = decodeP(input, inOff, p21);
        inOff = decodeAlpha(input, inOff, aAlpha);
        inOff = decodeAlpha(input, inOff, bAlpha);
        inOff = decodeAlpha(input, inOff, qAlpha1);
        inOff = decodeAlpha(input, inOff, qAlpha2);
        return inOff;
    }

    private int decodeP(byte[] input, int inOff, byte[][][][] p)
    {
        for (int i = 0; i < p.length; ++i)
        {
            inOff = decodeAlpha(input, inOff, p[i]);
        }
        return inOff;
    }

    private int decodeAlpha(byte[] input, int inOff, byte[][][] alpha)
    {
        for (int i = 0; i < alpha.length; ++i)
        {
            for (int j = 0; j < alpha[i].length; ++j)
            {
                GF16Utils.decode(input, inOff, alpha[i][j], 0, alpha[i][j].length);
                inOff += (alpha[i][j].length + 1) >> 1;
            }
        }
        return inOff;
    }

}
