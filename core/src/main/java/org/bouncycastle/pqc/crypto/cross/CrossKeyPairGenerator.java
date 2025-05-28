package org.bouncycastle.pqc.crypto.cross;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class CrossKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private CrossParameters p;
    private SecureRandom random;

    public void init(KeyGenerationParameters param)
    {
        this.p = ((CrossKeyGenerationParameters)param).getParameters();
        this.random = param.getRandom();
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        return null;
    }
}
