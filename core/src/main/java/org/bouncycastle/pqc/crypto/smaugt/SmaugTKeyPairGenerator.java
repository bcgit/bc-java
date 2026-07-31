package org.bouncycastle.pqc.crypto.smaugt;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class SmaugTKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SmaugTKeyGenerationParameters smaugTParams;
    private SecureRandom random;

    public void init(KeyGenerationParameters param)
    {
        this.smaugTParams = (SmaugTKeyGenerationParameters)param;
        this.random = param.getRandom();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        SmaugTParameters parameters = smaugTParams.getParameters();
        SmaugTEngine engine = parameters.getEngine();

        byte[] pk = new byte[engine.getPublicKeyBytes()];
        byte[] sk = new byte[engine.getKemSecretKeyBytes()];

        engine.cryptoKemKeypair(pk, sk, random);

        SmaugTPublicKeyParameters pubKey = new SmaugTPublicKeyParameters(parameters, pk);
        SmaugTPrivateKeyParameters privKey = new SmaugTPrivateKeyParameters(parameters, sk);
        return new AsymmetricCipherKeyPair(pubKey, privKey);
    }
}
