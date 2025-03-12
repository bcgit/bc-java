package org.bouncycastle.pqc.crypto.snova;

public class MapGroup2
{
    public final byte[][][][] f11;  // [m][v][v]
    public final byte[][][][] f12;  // [m][v][o]
    public final byte[][][][] f21;  // [m][o][v]

    public MapGroup2(SnovaParameters params)
    {
        int m = params.getM();
        int v = params.getV();
        int o = params.getO();
        int lsq = params.getL() * params.getL();
        f11 = new byte[m][v][v][lsq];
        f12 = new byte[m][v][o][lsq];
        f21 = new byte[m][o][v][lsq];
    }
}
