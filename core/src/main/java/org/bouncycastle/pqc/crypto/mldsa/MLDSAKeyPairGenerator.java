package org.bouncycastle.pqc.crypto.mldsa;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class MLDSAKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private MLDSAParameters parameters;
    private SecureRandom random;

    public void init(KeyGenerationParameters param)
    {
        this.parameters = ((MLDSAKeyGenerationParameters)param).getParameters();
        this.random = param.getRandom();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        MLDSAEngine engine = parameters.getEngine(random);

        byte[][] keyPair = engine.generateKeyPair();
        MLDSAPublicKeyParameters pubKey = new MLDSAPublicKeyParameters(parameters, keyPair[0], keyPair[6]);
        MLDSAPrivateKeyParameters privKey = new MLDSAPrivateKeyParameters(parameters, keyPair[0], keyPair[1], keyPair[2], keyPair[3], keyPair[4], keyPair[5], keyPair[6], keyPair[7]);

        return new AsymmetricCipherKeyPair(pubKey, privKey);
    }
}
