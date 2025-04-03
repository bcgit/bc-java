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

        SnovaKeyElements keyElements = new SnovaKeyElements(params);
        System.arraycopy(ptPublicKeySeed, 0, pk, 0, ptPublicKeySeed.length);
        engine.genMap1T12Map2(keyElements, ptPublicKeySeed, ptPrivateKeySeed);

        // Generate P22 matrix
        engine.genP22(pk, ptPublicKeySeed.length, keyElements.T12, keyElements.map1.p21, keyElements.map2.f12);


        // Pack public key components
        System.arraycopy(ptPublicKeySeed, 0, pk, 0, ptPublicKeySeed.length);

        if (params.isSkIsSeed())
        {
            sk = seedPair;
        }
        else
        {
            int o = params.getO();
            int lsq = params.getLsq();
            int v = params.getV();
            int length = o * params.getAlpha() * lsq * 4 + v * o * lsq + (o * v * v + o * v * o + o * o * v) * lsq;

            byte[] input = new byte[length];
            int inOff = 0;
            inOff = SnovaKeyElements.copy3d(keyElements.map1.aAlpha, input, inOff);
            inOff = SnovaKeyElements.copy3d(keyElements.map1.bAlpha, input, inOff);
            inOff = SnovaKeyElements.copy3d(keyElements.map1.qAlpha1, input, inOff);
            inOff = SnovaKeyElements.copy3d(keyElements.map1.qAlpha2, input, inOff);
            inOff = SnovaKeyElements.copy3d(keyElements.T12, input, inOff);
            inOff = SnovaKeyElements.copy4d(keyElements.map2.f11, input, inOff);
            inOff = SnovaKeyElements.copy4d(keyElements.map2.f12, input, inOff);
            SnovaKeyElements.copy4d(keyElements.map2.f21, input, inOff);
            GF16Utils.encodeMergeInHalf(input, length, sk);
            System.arraycopy(seedPair, 0, sk, sk.length - seedLength, seedLength);
        }

        return new AsymmetricCipherKeyPair(
            new SnovaPublicKeyParameters(params, pk),
            new SnovaPrivateKeyParameters(params, sk)
        );
    }
}
