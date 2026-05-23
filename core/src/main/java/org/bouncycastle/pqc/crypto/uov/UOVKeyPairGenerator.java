package org.bouncycastle.pqc.crypto.uov;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class UOVKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private UOVParameters params;
    private SecureRandom random;

    public void init(KeyGenerationParameters param)
    {
        UOVKeyGenerationParameters kgParams = (UOVKeyGenerationParameters)param;
        this.params = kgParams.getParameters();
        this.random = kgParams.getRandom();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        UOVEngine engine = new UOVEngine(params);
        byte[][] pair = engine.generateKeyPair(random);
        UOVPublicKeyParameters pub = new UOVPublicKeyParameters(params, pair[0]);
        UOVPrivateKeyParameters priv = new UOVPrivateKeyParameters(params, pair[1]);
        return new AsymmetricCipherKeyPair(pub, priv);
    }
}
