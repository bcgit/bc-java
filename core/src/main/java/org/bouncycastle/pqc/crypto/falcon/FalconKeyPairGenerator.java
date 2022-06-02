package org.bouncycastle.pqc.crypto.falcon;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class FalconKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{

    private SecureRandom random;
    private FalconKeyGenerationParameters falconParam;
    private FalconEngine engine;

    @Override
    public void init(KeyGenerationParameters param)
    {
        this.falconParam = (FalconKeyGenerationParameters)param;
        this.random = falconParam.getRandom();
        this.engine = falconParam.getParameters().getEngine();
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        byte[] seed = new byte[48];
        this.random.nextBytes(seed);
        FalconSHAKE256 rand = new FalconSHAKE256();
        rand.inject(seed, 48);
        rand.flip();
        FalconKeys keys = this.engine.keygen(rand);
        FalconPrivateKeyParameters sk = new FalconPrivateKeyParameters(falconParam.getParameters(), keys.f, keys.g, keys.F);
        FalconPublicKeyParameters pk = new FalconPublicKeyParameters(falconParam.getParameters(), keys.h);
        return new AsymmetricCipherKeyPair(pk, sk);
    }

}
