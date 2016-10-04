package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.Provider;
import java.security.SecureRandom;

import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

/**
 * Basic builder class for constructing standard TlsCrypto classes.
 */
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

    /**
     * Set the provider of cryptographic services for any TlsCrypto we build.
     *
     * @param provider the provider class to source cryptographic services from.
     * @return the current builder instance.
     */
    public JcaTlsCryptoBuilder setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    /**
     * Set the provider of cryptographic services for any TlsCrypto we build by name.
     *
     * @param providerName the name of the provider class to source cryptographic services from.
     * @return the current builder instance.
     */
    public JcaTlsCryptoBuilder setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    /**
     * Build a new TlsCrypto using the current builder configuration.
     *
     * @return a new TlsCrypto.
     */
    public JcaTlsCrypto build()
    {
        return new JcaTlsCrypto(helper, entropySource, nonceEntropySource);
    }
}
