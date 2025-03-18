package org.bouncycastle.pqc.crypto.snova;

class PublicKey
{
    public final byte[] publicKeySeed;
    public final byte[] P22;

    public PublicKey(SnovaParameters params)
    {
        publicKeySeed = new byte[SnovaKeyPairGenerator.publicSeedLength];
        P22 = new byte[(params.getM() * params.getO() * params.getO() * params.getL() * params.getL() + 1) >> 1];
    }
}

