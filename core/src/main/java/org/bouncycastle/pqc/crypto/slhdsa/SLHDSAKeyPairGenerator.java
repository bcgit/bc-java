package org.bouncycastle.pqc.crypto.slhdsa;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class SLHDSAKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;
    private SLHDSAParameters parameters;

    public void init(KeyGenerationParameters param)
    {
        random = param.getRandom();
        parameters = ((SLHDSAKeyGenerationParameters)param).getParameters();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        SLHDSAEngine engine = parameters.getEngine();
        byte[] pkSeed;
        SK sk;

        sk = new SK(sec_rand(engine.N), sec_rand(engine.N));
        pkSeed = sec_rand(engine.N);

        engine.init(pkSeed);

        // TODO
        PK pk = new PK(pkSeed, new HT(engine, sk.seed, pkSeed).htPubKey);

        return new AsymmetricCipherKeyPair(new SLHDSAPublicKeyParameters(parameters, pk),
            new SLHDSAPrivateKeyParameters(parameters, sk, pk));
    }

    private byte[] sec_rand(int n)
    {
        byte[] rv = new byte[n];

        random.nextBytes(rv);

        return rv;
    }
}
