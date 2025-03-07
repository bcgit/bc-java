package org.bouncycastle.pqc.crypto.snova;

class SKGF16
{
    public final GF16Matrix[][] Aalpha;  // [m][alpha]
    public final GF16Matrix[][] Balpha;  // [m][alpha]
    public final GF16Matrix[][] Qalpha1; // [m][alpha]
    public final GF16Matrix[][] Qalpha2; // [m][alpha]
    public final GF16Matrix[][] T12;     // [v][o]
    public final GF16Matrix[][][] F11;   // [m][v][v]
    public final GF16Matrix[][][] F12;   // [m][v][o]
    public final GF16Matrix[][][] F21;   // [m][o][v]
    public final byte[] publicKeySeed;
    public final byte[] privateKeySeed;

    public SKGF16(SnovaParameters params)
    {
        int m = params.getM();
        int v = params.getV();
        int o = params.getO();
        int alpha = params.getAlpha();
        int rank = params.getL();

        Aalpha = GF16Utils.create2DArray(m, alpha, rank);
        Balpha = GF16Utils.create2DArray(m, alpha, rank);
        Qalpha1 = GF16Utils.create2DArray(m, alpha, rank);
        Qalpha2 = GF16Utils.create2DArray(m, alpha, rank);
        T12 = GF16Utils.create2DArray(v, o, rank);
        F11 = GF16Utils.create3DArray(m, v, v, rank);
        F12 = GF16Utils.create3DArray(m, v, o, rank);
        F21 = GF16Utils.create3DArray(m, o, v, rank);

        publicKeySeed = new byte[SnovaKeyPairGenerator.publicSeedLength];
        privateKeySeed = new byte[SnovaKeyPairGenerator.privateSeedLength];
    }
}
