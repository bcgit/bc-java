package org.bouncycastle.pqc.crypto.snova;

class SnovaKeyElements
{
    public final MapGroup1 map1;
    public final byte[][][] T12;     // [v][o]
    public final MapGroup2 map2;
    public final PublicKey publicKey;

    public SnovaKeyElements(SnovaParameters params)
    {
        map1 = new MapGroup1(params);
        T12 = new byte[params.getV()][params.getO()][16];
        map2 = new MapGroup2(params);
        publicKey = new PublicKey(params);
    }
}
