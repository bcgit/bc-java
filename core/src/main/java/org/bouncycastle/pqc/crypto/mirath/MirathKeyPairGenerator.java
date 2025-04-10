package org.bouncycastle.pqc.crypto.mirath;


import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;


public class MirathKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private MirathParameters p;
    private SecureRandom random;

    @Override
    public void init(KeyGenerationParameters param)
    {
        this.p = ((MirathKeyGenerationParameters)param).getParameters();
        this.random = param.getRandom();
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        return null;
    }
}
