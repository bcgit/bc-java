package org.bouncycastle.pqc.crypto.snova;

public class MapGroup2
{
    public final GF16Matrix[][][] F11;  // [m][v][v]
    public final GF16Matrix[][][] F12;  // [m][v][o]
    public final GF16Matrix[][][] F21;  // [m][o][v]

    public MapGroup2(SnovaParameters params)
    {
        int m = params.getM();
        int v = params.getV();
        int o = params.getO();
        int rank = params.getL();

        F11 = GF16Utils.create3DArray(m, v, v, rank);
        F12 = GF16Utils.create3DArray(m, v, o, rank);
        F21 = GF16Utils.create3DArray(m, o, v, rank);
    }
}
