package org.bouncycastle.pqc.crypto.crystals.dilithium;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class DilithiumKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private DilithiumParameters dilithiumParams;

    private SecureRandom random;

    private void initialize(
        KeyGenerationParameters param)
    {
        this.dilithiumParams = ((DilithiumKeyGenerationParameters)param).getParameters();
        this.random = param.getRandom();

    }

    private AsymmetricCipherKeyPair genKeyPair()
    {
        DilithiumEngine engine = dilithiumParams.getEngine(random);

        byte[][] keyPair = engine.generateKeyPair();
        // System.out.println("pk gen = ");
        // Helper.printByteArray(keyPair[0]);

        DilithiumPublicKeyParameters pubKey = new DilithiumPublicKeyParameters(dilithiumParams, keyPair[0], keyPair[6]);
        DilithiumPrivateKeyParameters privKey = new DilithiumPrivateKeyParameters(dilithiumParams, keyPair[0], keyPair[1], keyPair[2], keyPair[3], keyPair[4], keyPair[5], keyPair[6]);

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
