package org.bouncycastle.pqc.crypto.snova;

class MapGroup1
{
    public final GF16Matrix[][][] P11;  // [m][v][v]
    public final GF16Matrix[][][] P12;  // [m][v][o]
    public final GF16Matrix[][][] P21;  // [m][o][v]
    public final GF16Matrix[][] Aalpha; // [m][alpha]
    public final GF16Matrix[][] Balpha; // [m][alpha]
    public final GF16Matrix[][] Qalpha1;// [m][alpha]
    public final GF16Matrix[][] Qalpha2;// [m][alpha]

    public MapGroup1(SnovaParameters params)
    {
        int m = params.getM();
        int v = params.getV();
        int o = params.getO();
        int alpha = params.getAlpha();
        int rank = params.getL();

        P11 = GF16Utils.create3DArray(m, v, v, rank);
        P12 = GF16Utils.create3DArray(m, v, o, rank);
        P21 = GF16Utils.create3DArray(m, o, v, rank);
        Aalpha = GF16Utils.create2DArray(m, alpha, rank);
        Balpha = GF16Utils.create2DArray(m, alpha, rank);
        Qalpha1 = GF16Utils.create2DArray(m, alpha, rank);
        Qalpha2 = GF16Utils.create2DArray(m, alpha, rank);
    }
}
