package org.bouncycastle.pqc.crypto.sike;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class SIKEKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SIKEKeyGenerationParameters sikeParams;

    private SecureRandom random;

    private void initialize(KeyGenerationParameters param)
    {
        this.sikeParams = (SIKEKeyGenerationParameters)param;
        this.random = param.getRandom();
    }

    private AsymmetricCipherKeyPair genKeyPair()
    {
        SIKEEngine engine = sikeParams.getParameters().getEngine();
        byte[] sk = new byte[engine.getPrivateKeySize()];
        byte[] pk = new byte[engine.getPublicKeySize()];

        engine.crypto_kem_keypair(pk, sk, random);


        SIKEPublicKeyParameters pubKey = new SIKEPublicKeyParameters(sikeParams.getParameters(), pk);
        SIKEPrivateKeyParameters privKey = new SIKEPrivateKeyParameters(sikeParams.getParameters(), sk);
        return new AsymmetricCipherKeyPair(pubKey, privKey);
    }

    public void init(KeyGenerationParameters param)
    {
        this.initialize(param);
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        return genKeyPair();
    }
}
