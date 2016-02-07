package org.bouncycastle.pqc.crypto.sphincs;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class SPHINCS256KeyGenerationParameters
    extends KeyGenerationParameters
{
    private final Digest treeDigest;

    public SPHINCS256KeyGenerationParameters(SecureRandom random, Digest treeDigest)
    {
        super(random, SPHINCS256Config.CRYPTO_PUBLICKEYBYTES * 8);
        this.treeDigest = treeDigest;
    }

    public Digest getTreeDigest()
    {
        return treeDigest;
    }
}
