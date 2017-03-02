package org.bouncycastle.est.jcajce;

import java.security.Provider;
import java.security.SecureRandom;

import org.bouncycastle.est.HttpAuth;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * Builder for HttpAuth operator that handles digest auth using a JCA provider.
 */
public class JcaHttpAuthBuilder
{
    private JcaDigestCalculatorProviderBuilder providerBuilder = new JcaDigestCalculatorProviderBuilder();

    private final String realm;
    private final String username;
    private final char[] password;
    private SecureRandom random = new SecureRandom();

    /**
     * Base constructor for digest auth.
     *
     * @param username user id.
     * @param password user's password.
     */
    public JcaHttpAuthBuilder(String username, char[] password)
    {
        this(null, username, password);
    }

    /**
     * Base constructor for digest auth with an expected realm.
     *
     * @param realm    expected server realm.
     * @param username user id.
     * @param password user's password.
     */
    public JcaHttpAuthBuilder(String realm, String username, char[] password)
    {
        this.realm = realm;
        this.username = username;
        this.password = password;
    }

    /**
     * Set the provider to use to provide the needed message digests.
     *
     * @param provider provider to use.
     * @return this builder instance.
     */
    public JcaHttpAuthBuilder setProvider(Provider provider)
    {
        this.providerBuilder.setProvider(provider);

        return this;
    }

    /**
     * Set the provider to use to provide the needed message digests.
     *
     * @param providerName the name provider to use.
     * @return this builder instance.
     */
    public JcaHttpAuthBuilder setProvider(String providerName)
    {
        this.providerBuilder.setProvider(providerName);

        return this;
    }

    /**
     * Set the SecureRandom to be used as a source of nonces.
     *
     * @param random the secure random to use as a nonce generator.
     * @return this builder instance.
     */
    public JcaHttpAuthBuilder setNonceGenerator(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    /**
     * Return a HttpAuth implementing digest auth for the user, password, and realm combination.
     *
     * @return a HttpAuth object.
     * @throws OperatorCreationException if there is an issue setting up access to digest operators.
     */
    public HttpAuth build()
        throws OperatorCreationException
    {
        return new HttpAuth(realm, username, password, random, providerBuilder.build());
    }
}
