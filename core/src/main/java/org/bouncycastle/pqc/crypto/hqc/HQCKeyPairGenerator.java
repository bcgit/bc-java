package org.bouncycastle.pqc.crypto.hqc;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class HQCKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{

    private HQCKeyGenerationParameters hqcKeyGenerationParameters;

    private SecureRandom random;

    @Override
    public void init(KeyGenerationParameters params)
    {
        this.hqcKeyGenerationParameters = (HQCKeyGenerationParameters)params;
        this.random = params.getRandom();
    }

    private AsymmetricCipherKeyPair genKeyPair()
    {
        HQCEngine engine = hqcKeyGenerationParameters.getParameters().getEngine();
        byte[] pk = new byte[hqcKeyGenerationParameters.getParameters().getPublicKeyBytes()];
        byte[] sk = new byte[hqcKeyGenerationParameters.getParameters().getSecretKeyBytes()];

        engine.genKeyPair(pk, sk, random);

        // form keys
        HQCPublicKeyParameters publicKey = new HQCPublicKeyParameters(hqcKeyGenerationParameters.getParameters(), pk);
        HQCPrivateKeyParameters privateKey = new HQCPrivateKeyParameters(hqcKeyGenerationParameters.getParameters(), sk);

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        return genKeyPair();
    }
}
