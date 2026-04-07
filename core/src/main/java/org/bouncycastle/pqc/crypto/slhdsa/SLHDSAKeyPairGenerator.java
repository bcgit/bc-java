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
        return SLHDSAEngine.implGenerateKeyPair(parameters, skSeed, skPrf, pkSeed);
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        byte[] skSeed = sec_rand(parameters.getN());
        byte[] skPrf = sec_rand(parameters.getN());
        byte[] pkSeed = sec_rand(parameters.getN());

        return SLHDSAEngine.implGenerateKeyPair(parameters, skSeed, skPrf, pkSeed);
    }

    private byte[] sec_rand(int n)
    {
        byte[] rv = new byte[n];

        random.nextBytes(rv);

        return rv;
    }
}
