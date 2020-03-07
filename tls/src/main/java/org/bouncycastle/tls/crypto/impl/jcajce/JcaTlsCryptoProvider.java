package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;

import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.tls.crypto.TlsCryptoProvider;

/**
 * Basic builder class for constructing standard JcaTlsCrypto classes.
 */
public class JcaTlsCryptoProvider
    implements TlsCryptoProvider
{
    private JcaJceHelper helper = new DefaultJcaJceHelper();

    public JcaTlsCryptoProvider()
    {
    }

    /**
     * Set the provider of cryptographic services for any JcaTlsCrypto we build.
     *
     * @param provider the provider class to source cryptographic services from.
     * @return the current builder instance.
     */
    public JcaTlsCryptoProvider setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    /**
     * Set the provider of cryptographic services for any JcaTlsCrypto we build by name.
     *
     * @param providerName the name of the provider class to source cryptographic services from.
     * @return the current builder instance.
     */
    public JcaTlsCryptoProvider setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    /**
     * Create a new JcaTlsCrypto using the current builder configuration and the passed in entropy source..
     *
     * @param random SecureRandom for generating key material and seeds for nonce generation.
     * @return a new JcaTlsCrypto.
     */
    public JcaTlsCrypto create(SecureRandom random)
    {
        try
        {
            if (random == null)
            {
                if (helper instanceof DefaultJcaJceHelper)
                {
                    random = SecureRandom.getInstance("DEFAULT");
                }
                else
                {
                    random = SecureRandom.getInstance("DEFAULT", helper.createDigest("SHA-512").getProvider());
                }
            }

            return create(random, new NonceEntropySource(helper, random));
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException("unable to create JcaTlsCrypto: " + e.getMessage(), e);
        }
    }

    /**
     * Create a new JcaTlsCrypto using the current builder configuration.
     *
     * @param keyRandom SecureRandom for generating key material.
     * @param nonceRandom SecureRandom for generating nonces.
     * @return a new JcaTlsCrypto.
     */
    public JcaTlsCrypto create(SecureRandom keyRandom, SecureRandom nonceRandom)
    {
        return new JcaTlsCrypto(helper, keyRandom, nonceRandom);
    }

    public JcaJceHelper getHelper()
    {
        return helper;
    }

    @SuppressWarnings("serial")
    private static class NonceEntropySource
       extends SecureRandom
    {
        NonceEntropySource(JcaJceHelper helper, SecureRandom random)
            throws GeneralSecurityException
        {
            super(new NonceEntropySourceSpi(random, helper.createDigest("SHA-512")), random.getProvider());
        }

        private static class NonceEntropySourceSpi
            extends SecureRandomSpi
        {
            private final SecureRandom source;
            private final MessageDigest digest;

            private final byte[] seed;
            private final byte[] state;

            NonceEntropySourceSpi(SecureRandom source, MessageDigest digest)
            {
                this.source = source;
                this.digest = digest;

                this.seed = source.generateSeed(digest.getDigestLength());
                this.state = new byte[seed.length];
            }

            protected void engineSetSeed(byte[] bytes)
            {
                synchronized (digest)
                {
                    runDigest(seed, bytes, seed);
                }
            }

            protected void engineNextBytes(byte[] bytes)
            {
                synchronized (digest)
                {
                    int stateOff = state.length;
    
                    for (int i = 0; i != bytes.length; i++)
                    {
                        if (stateOff == state.length)
                        {
                            source.nextBytes(state);
                            runDigest(seed, state, state);
                            stateOff = 0;
                        }
                        bytes[i] = state[stateOff++];
                    }
                }
            }

            protected byte[] engineGenerateSeed(int seedLen)
            {
                return source.generateSeed(seedLen);
            }

            private void runDigest(byte[] x, byte[] y, byte[] z)
            {
                digest.update(x);
                digest.update(y);

                try
                {
                    digest.digest(z, 0, z.length);
                }
                catch (DigestException e)
                {
                    throw Exceptions.illegalStateException("unable to generate nonce data: " + e.getMessage(), e);
                }
            }
        }
    }
}
