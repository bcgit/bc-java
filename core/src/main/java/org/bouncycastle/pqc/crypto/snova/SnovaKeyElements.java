package org.bouncycastle.pqc.crypto.snova;

class SnovaKeyElements
{
    public final MapGroup1 map1;
    public final GF16Matrix[][] T12;     // [v][o]
    public final MapGroup2 map2;
    public final PublicKey publicKey;

    public SnovaKeyElements(SnovaParameters params)
    {
        map1 = new MapGroup1(params);
        T12 = GF16Utils.create2DArray(params.getV(), params.getO(), params.getL());
        map2 = new MapGroup2(params);
        publicKey = new PublicKey(params);
    }
}
