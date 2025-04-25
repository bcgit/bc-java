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

    public AsymmetricCipherKeyPair internalGenerateKeyPair(byte[] skSeed, byte[] skPrf, byte[] pkSeed)
    {
        return implGenerateKeyPair(parameters.getEngine(), skSeed, skPrf, pkSeed);
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        SLHDSAEngine engine = parameters.getEngine();

        byte[] skSeed = sec_rand(engine.N);
        byte[] skPrf = sec_rand(engine.N);
        byte[] pkSeed = sec_rand(engine.N);

        return implGenerateKeyPair(engine, skSeed, skPrf, pkSeed);
    }

    private AsymmetricCipherKeyPair implGenerateKeyPair(SLHDSAEngine engine, byte[] skSeed, byte[] skPrf, byte[] pkSeed)
    {
        SK sk = new SK(skSeed, skPrf);

        engine.init(pkSeed);

        // TODO
        PK pk = new PK(pkSeed, new HT(engine, sk.seed, pkSeed).htPubKey);

        return new AsymmetricCipherKeyPair(
            new SLHDSAPublicKeyParameters(parameters, pk),
            new SLHDSAPrivateKeyParameters(parameters, sk, pk));
    }

    private byte[] sec_rand(int n)
    {
        byte[] rv = new byte[n];

        random.nextBytes(rv);

        return rv;
    }
}
