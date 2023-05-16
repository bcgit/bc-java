package org.bouncycastle.pqc.crypto.lms;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class LMSKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    LMSKeyGenerationParameters param;

    public void init(KeyGenerationParameters param)
    {
        this.param = (LMSKeyGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        SecureRandom source = param.getRandom();

        byte[] I = new byte[16];
        source.nextBytes(I);

        LMSigParameters sigParameter = param.getParameters().getLMSigParam();
        byte[] rootSecret = new byte[sigParameter.getM()];
        source.nextBytes(rootSecret);

        LMSPrivateKeyParameters privKey = LMS.generateKeys(sigParameter, param.getParameters().getLMOTSParam(), 0, I, rootSecret);

        return new AsymmetricCipherKeyPair(privKey.getPublicKey(), privKey);
    }
}
