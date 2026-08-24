package org.bouncycastle.crypto.generators;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.LMSKeyGenerationParameters;
import org.bouncycastle.crypto.params.LMSPrivateKeyParameters;
import org.bouncycastle.crypto.params.LMSigParameters;
import org.bouncycastle.crypto.signers.lms.LMS;

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
