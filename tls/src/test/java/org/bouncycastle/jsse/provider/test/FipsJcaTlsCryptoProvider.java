package org.bouncycastle.jsse.provider.test;

import java.security.SecureRandom;

import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

public class FipsJcaTlsCryptoProvider extends JcaTlsCryptoProvider
{
    @Override
    public JcaTlsCrypto create(SecureRandom keyRandom, SecureRandom nonceRandom)
    {
        return new FipsJcaTlsCrypto(getHelper(), keyRandom, nonceRandom);
    }
}
