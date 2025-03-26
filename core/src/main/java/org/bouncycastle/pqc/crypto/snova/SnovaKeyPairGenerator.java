package org.bouncycastle.pqc.crypto.snova;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.util.Arrays;

public class SnovaKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SnovaEngine engine;
    private static final int seedLength = 48;
    static final int publicSeedLength = 16;
    static final int privateSeedLength = 32;
    private SnovaParameters params;
    private SecureRandom random;
    private boolean initialized;

    @Override
    public void init(KeyGenerationParameters param)
    {
        SnovaKeyGenerationParameters snovaParams = (SnovaKeyGenerationParameters)param;
        this.params = snovaParams.getParameters();
        this.random = snovaParams.getRandom();
        this.initialized = true;
        this.engine = new SnovaEngine(params);
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        if (!initialized)
        {
            throw new IllegalStateException("SNOVA key pair generator not initialized");
        }

        // Generate seed pair according to SNOVA specifications
        byte[] seedPair = new byte[seedLength];
        random.nextBytes(seedPair);

        byte[] pk = new byte[params.getPublicKeyLength()];
        byte[] sk = new byte[params.getPrivateKeyLength()];

        byte[] ptPublicKeySeed = Arrays.copyOfRange(seedPair, 0, publicSeedLength);
        byte[] ptPrivateKeySeed = Arrays.copyOfRange(seedPair, publicSeedLength, seedPair.length);

        SnovaKeyElements keyElements = new SnovaKeyElements(params, engine);
        generateKeysCore(keyElements, ptPublicKeySeed, ptPrivateKeySeed);

        // Pack public key components
        System.arraycopy(ptPublicKeySeed, 0, pk, 0, ptPublicKeySeed.length);
        System.arraycopy(keyElements.publicKey.P22, 0, pk, ptPublicKeySeed.length, keyElements.publicKey.P22.length);

        if (params.isSkIsSeed())
        {
            sk = seedPair;
        }
        else
        {
            keyElements.encodeMergerInHalf(sk);
            System.arraycopy(seedPair, 0, sk, sk.length - seedLength, seedLength);
        }

        return new AsymmetricCipherKeyPair(
            new SnovaPublicKeyParameters(params, pk),
            new SnovaPrivateKeyParameters(params, sk)
        );
    }

    private void generateKeysCore(SnovaKeyElements keyElements, byte[] pkSeed, byte[] skSeed)
    {
        // Generate T12 matrix
        engine.genSeedsAndT12(keyElements.T12, skSeed);

        // Generate map components
        engine.genABQP(keyElements.map1, pkSeed, keyElements.fixedAbq);

        // Generate F matrices
        engine.genF(keyElements.map2, keyElements.map1, keyElements.T12);

        // Generate P22 matrix
        engine.genP22(keyElements.publicKey.P22, keyElements.T12, keyElements.map1.p21, keyElements.map2.f12);
    }
}
