package org.bouncycastle.jsse.provider.test;

import java.security.SecureRandom;

import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.crypto.impl.AEADNonceGeneratorFactory;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.test.TestAEADGeneratorFactory;

public class FipsJcaTlsCrypto extends JcaTlsCrypto
{
    public FipsJcaTlsCrypto(JcaJceHelper helper, SecureRandom entropySource, SecureRandom nonceEntropySource)
    {
        super(helper, entropySource, nonceEntropySource);
    }

    @Override
    public AEADNonceGeneratorFactory getFipsGCMNonceGeneratorFactory()
    {
        return FipsTestUtils.enableGCMCiphersIn12 ? TestAEADGeneratorFactory.INSTANCE : null;
    }
}
