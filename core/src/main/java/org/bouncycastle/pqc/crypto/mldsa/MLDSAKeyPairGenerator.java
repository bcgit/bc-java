package org.bouncycastle.pqc.crypto.mldsa;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class MLDSAKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private MLDSAParameters dilithiumParams;

    private SecureRandom random;

    private void initialize(
        KeyGenerationParameters param)
    {
        this.dilithiumParams = ((MLDSAKeyGenerationParameters)param).getParameters();
        this.random = param.getRandom();
    }

    private AsymmetricCipherKeyPair genKeyPair()
    {
        MLDSAEngine engine = dilithiumParams.getEngine(random);

        byte[][] keyPair = engine.generateKeyPair();
        // System.out.println("pk gen = ");
        // Helper.printByteArray(keyPair[0]);

        MLDSAPublicKeyParameters pubKey = new MLDSAPublicKeyParameters(dilithiumParams, keyPair[0], keyPair[6]);
        MLDSAPrivateKeyParameters privKey = new MLDSAPrivateKeyParameters(dilithiumParams, keyPair[0], keyPair[1], keyPair[2], keyPair[3], keyPair[4], keyPair[5], keyPair[6]);

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
    public AsymmetricCipherKeyPair internalGenerateKeyPair(byte[] seed)
    {
        MLDSAEngine engine = dilithiumParams.getEngine(random);

        byte[][] keyPair = engine.generateKeyPairInternal(seed);
        // System.out.println("pk gen = ");
        // Helper.printByteArray(keyPair[0]);

        MLDSAPublicKeyParameters pubKey = new MLDSAPublicKeyParameters(dilithiumParams, keyPair[0], keyPair[6]);
        MLDSAPrivateKeyParameters privKey = new MLDSAPrivateKeyParameters(dilithiumParams, keyPair[0], keyPair[1], keyPair[2], keyPair[3], keyPair[4], keyPair[5], keyPair[6]);

        return new AsymmetricCipherKeyPair(pubKey, privKey);
    }
}
