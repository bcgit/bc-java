package org.bouncycastle.pqc.crypto.snova;

class SnovaKeyElements
{
    public final MapGroup1 map1;
    public final byte[][][] T12;     // [v][o]
    public final MapGroup2 map2;
    public final PublicKey publicKey;
    private final int length;

    public SnovaKeyElements(SnovaParameters params)
    {
        int o = params.getO();
        int l = params.getL();
        int v = params.getV();
        int lsq = l * l;
        map1 = new MapGroup1(params);
        T12 = new byte[v][o][lsq];
        map2 = new MapGroup2(params);
        publicKey = new PublicKey(params);
        length = o * params.getAlpha() * lsq * 4 + v * o * lsq + (o * v * v + o * v * o + o * o * v) * lsq;
    }

    public void encodeMergerInHalf(byte[] output)
    {
        byte[] input = new byte[length];
        int inOff = 0;
        inOff = copy3d(map1.aAlpha, input, inOff);
        inOff = copy3d(map1.bAlpha, input, inOff);
        inOff = copy3d(map1.qAlpha1, input, inOff);
        inOff = copy3d(map1.qAlpha2, input, inOff);
        inOff = copy3d(T12, input, inOff);
        inOff = copy4d(map2.f11, input, inOff);
        inOff = copy4d(map2.f12, input, inOff);
        inOff = copy4d(map2.f21, input, inOff);
        GF16Utils.encodeMergeInHalf(input, length, output);
    }

    public int copy3d(byte[][][] alpha, byte[] output, int outOff)
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

    public int copy4d(byte[][][][] alpha, byte[] output, int outOff)
    {
        for (int i = 0; i < alpha.length; ++i)
        {
            outOff = copy3d(alpha[i], output, outOff);
        }
        return outOff;
    }
}
