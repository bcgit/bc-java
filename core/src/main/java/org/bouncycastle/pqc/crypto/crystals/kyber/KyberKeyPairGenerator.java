package org.bouncycastle.pqc.crypto.crystals.kyber;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class KyberKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private KyberParameters kyberParams;

    private SecureRandom random;

    private void initialize(
        KeyGenerationParameters param)
    {
        this.kyberParams = ((KyberKeyGenerationParameters)param).getParameters();
        this.random = param.getRandom();

    }

    private AsymmetricCipherKeyPair genKeyPair()
    {
        KyberEngine engine = kyberParams.getEngine();

        engine.init(random);

        byte[][] keyPair = engine.generateKemKeyPair();

        KyberPublicKeyParameters pubKey = new KyberPublicKeyParameters(kyberParams, keyPair[0], keyPair[1]);
        KyberPrivateKeyParameters privKey = new KyberPrivateKeyParameters(kyberParams,  keyPair[2], keyPair[3], keyPair[4], keyPair[0], keyPair[1]);
        
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
