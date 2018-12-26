package org.bouncycastle.pqc.crypto.sphincs;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class SPHINCS256KeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;
    private Digest treeDigest;

    public void init(KeyGenerationParameters param)
    {
        random = param.getRandom();
        treeDigest = ((SPHINCS256KeyGenerationParameters)param).getTreeDigest();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        Tree.leafaddr a = new Tree.leafaddr();

        byte[] sk = new byte[SPHINCS256Config.CRYPTO_SECRETKEYBYTES];

        random.nextBytes(sk);

        byte[] pk = new byte[SPHINCS256Config.CRYPTO_PUBLICKEYBYTES];

        System.arraycopy(sk, SPHINCS256Config.SEED_BYTES, pk, 0, Horst.N_MASKS * SPHINCS256Config.HASH_BYTES);

        // Initialization of top-subtree address
        a.level = SPHINCS256Config.N_LEVELS - 1;
        a.subtree = 0;
        a.subleaf = 0;

        HashFunctions hs = new HashFunctions(treeDigest);

        // Format pk: [|N_MASKS*params.HASH_BYTES| Bitmasks || root]
        // Construct top subtree
        Tree.treehash(hs, pk, (Horst.N_MASKS * SPHINCS256Config.HASH_BYTES), SPHINCS256Config.SUBTREE_HEIGHT, sk, a, pk, 0);

        return new AsymmetricCipherKeyPair(new SPHINCSPublicKeyParameters(pk, treeDigest.getAlgorithmName()),
                            new SPHINCSPrivateKeyParameters(sk, treeDigest.getAlgorithmName()));
    }
}
