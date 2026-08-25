package org.bouncycastle.crypto.generators;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.LMSKeyGenerationParameters;
import org.bouncycastle.crypto.params.LMSPrivateKeyParameters;
import org.bouncycastle.crypto.params.LMSigParameters;

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

        // RFC 8554 sec. 5.2, Algorithm 5: a fresh tree starts at q = 0 and has 2^h one-time keys.
        LMSPrivateKeyParameters privKey = new LMSPrivateKeyParameters(
            sigParameter, param.getParameters().getLMOTSParam(), 0, I, 1 << sigParameter.getH(), rootSecret);

        return new AsymmetricCipherKeyPair(privKey.getPublicKey(), privKey);
    }
}
