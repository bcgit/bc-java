package org.bouncycastle.pqc.crypto.snova;

class PublicKeyExpanded
{
    public final byte[] publicKeySeed;
    public final GF16Matrix[][][] P22;  // [m][o][o]
    public final MapGroup1 map1;

    public PublicKeyExpanded(SnovaParameters params)
    {
        int m = params.getM();
        int o = params.getO();
        int rank = params.getL();

        publicKeySeed = new byte[SnovaKeyPairGenerator.publicSeedLength];
        P22 = GF16Utils.create3DArray(m, o, o, rank);
        map1 = new MapGroup1(params);
    }
}
