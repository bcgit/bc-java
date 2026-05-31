package org.bouncycastle.pqc.crypto.haetae;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class HAETAEKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private HAETAEParameters p;
    private SecureRandom random;

    public void init(KeyGenerationParameters param)
    {
        this.p = ((HAETAEKeyGenerationParameters)param).getParameters();
        this.random = param.getRandom();
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        HAETAEEngine engine = new HAETAEEngine(p);
        byte[] pk = new byte[p.getPublicKeyBytes()];
        byte[] sk = new byte[p.getSecretKeyBytes()];
        byte[] seed = new byte[32];
        random.nextBytes(seed);
        engine.cryptoSignKeypairInternal(pk, sk, seed);
        return new AsymmetricCipherKeyPair(new HAETAEPublicKeyParameters(p, pk), new HAETAEPrivateKeyParameters(p, sk));
    }
}
