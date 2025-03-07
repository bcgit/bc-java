package org.bouncycastle.pqc.crypto.snova;

class PublicKeyExpandedPack
{
    public final byte[] publicKeySeed;
    public final byte[] packedData;

    public PublicKeyExpandedPack(SnovaParameters params)
    {
        publicKeySeed = new byte[SnovaKeyPairGenerator.publicSeedLength];
        int m = params.getM();
        int o = params.getO();
        int v = params.getV();
        int alpha = params.getAlpha();
        packedData = new byte[(((m * o * o) << 4) + // P22_t
            (m * v * v * 16 + m * v * o * 16 + m * o * v * 16 + m * alpha * 16 * 4) // map_group1
            + 1) >> 1];
    }
}
