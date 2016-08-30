package org.bouncycastle.tls.crypto.jcajce;

import java.security.Provider;
import java.security.SecureRandom;

import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

public class JcaTlsCryptoBuilder
{
    private final SecureRandom entropySource;
    private final SecureRandom nonceEntropySource;

    private JcaJceHelper helper = new DefaultJcaJceHelper();

    public JcaTlsCryptoBuilder(SecureRandom entropySource, SecureRandom nonceEntropySource)
    {
        this.entropySource = entropySource;
        this.nonceEntropySource = nonceEntropySource;
    }

    public JcaTlsCryptoBuilder setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    public JcaTlsCryptoBuilder setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    public JcaTlsCrypto build()
    {
        return new JcaTlsCrypto(helper, entropySource, nonceEntropySource);
    }
}
