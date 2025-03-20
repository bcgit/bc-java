package org.bouncycastle.pqc.crypto.snova;

import org.bouncycastle.crypto.digests.SHAKEDigest;

class SnovaKeyElements
{
    public final MapGroup1 map1;
    public final byte[][][] T12;     // [v][o]
    public final MapGroup2 map2;
    public final PublicKey publicKey;
    private final int length;
    byte[] fixedAbq;

    public SnovaKeyElements(SnovaParameters params, SnovaEngine engine)
    {
        int o = params.getO();
        int l = params.getL();
        int v = params.getV();
        int alpha = params.getAlpha();
        int lsq = l * l;
        map1 = new MapGroup1(params);
        T12 = new byte[v][o][lsq];
        map2 = new MapGroup2(params);
        publicKey = new PublicKey(params);
        length = o * params.getAlpha() * lsq * 4 + v * o * lsq + (o * v * v + o * v * o + o * o * v) * lsq;
        if (l < 4)
        {
            fixedAbq = new byte[4 * o * alpha * lsq];
            //genABQ(byte[] abqSeed)
            byte[] rngOut = new byte[o * alpha * (lsq + l)];
            byte[] q12 = new byte[2 * o * alpha * l];
            byte[] seed = "SNOVA_ABQ".getBytes();
            SHAKEDigest shake = new SHAKEDigest(256);
            shake.update(seed, 0, seed.length);
            shake.doFinal(rngOut, 0, rngOut.length);
            GF16Utils.decode(rngOut, fixedAbq, 2 * o * alpha * lsq);
            GF16Utils.decode(rngOut, alpha * lsq, q12, 2 * o * alpha * l);
            // Post-processing for invertible matrices
            for (int pi = 0; pi < o; ++pi)
            {
                for (int a = 0; a < alpha; ++a)
                {
                    engine.makeInvertibleByAddingAS(fixedAbq, (pi * alpha + a) * lsq);
                }
                for (int a = 0; a < alpha; ++a)
                {
                    engine.makeInvertibleByAddingAS(fixedAbq, ((o + pi) * alpha + a) * lsq);
                }

                for (int a = 0; a < alpha; ++a)
                {
                    engine.genAFqS(q12, (pi * alpha + a) * l, fixedAbq, ((2 * o + pi) * alpha + a) * lsq);
                }

                for (int a = 0; a < alpha; ++a)
                {
                    engine.genAFqS(q12, ((o + pi) * alpha + a) * l, fixedAbq, ((3 * o + pi) * alpha + a) * lsq);
                }
            }
        }
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
