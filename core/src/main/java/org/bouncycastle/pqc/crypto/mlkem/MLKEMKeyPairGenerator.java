package org.bouncycastle.pqc.crypto.mlkem;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class MLKEMKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private MLKEMParameters kyberParams;

    private SecureRandom random;

    private void initialize(
        KeyGenerationParameters param)
    {
        this.kyberParams = ((MLKEMKeyGenerationParameters)param).getParameters();
        this.random = param.getRandom();

    }

    private AsymmetricCipherKeyPair genKeyPair()
    {
        MLKEMEngine engine = kyberParams.getEngine();

        engine.init(random);

        byte[][] keyPair = engine.generateKemKeyPair();

        MLKEMPublicKeyParameters pubKey = new MLKEMPublicKeyParameters(kyberParams, keyPair[0], keyPair[1]);
        MLKEMPrivateKeyParameters privKey = new MLKEMPrivateKeyParameters(kyberParams,  keyPair[2], keyPair[3], keyPair[4], keyPair[0], keyPair[1]);
        
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

    public AsymmetricCipherKeyPair internalGenerateKeyPair(byte[] d, byte[] z)
    {
        byte[][] keyPair = kyberParams.getEngine().generateKemKeyPairInternal(d, z);

        MLKEMPublicKeyParameters pubKey = new MLKEMPublicKeyParameters(kyberParams, keyPair[0], keyPair[1]);
        MLKEMPrivateKeyParameters privKey = new MLKEMPrivateKeyParameters(kyberParams,  keyPair[2], keyPair[3], keyPair[4], keyPair[0], keyPair[1]);

        return new AsymmetricCipherKeyPair(pubKey, privKey);
    }

}
