package org.bouncycastle.est.jcajce;

import java.security.Provider;
import java.security.SecureRandom;

import org.bouncycastle.est.HttpAuth;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class JcaHttpAuthBuilder
{
    private JcaJceHelper helper = new DefaultJcaJceHelper();

    private final String realm;
    private final String username;
    private final char[] password;
    private SecureRandom random;

    public JcaHttpAuthBuilder(String username, char[] password)
    {
        this(null, username, password);
    }

    public JcaHttpAuthBuilder(String realm, String username, char[] password)
    {
        this.realm = realm;
        this.username = username;
        this.password = password;
    }

    public JcaHttpAuthBuilder setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    public JcaHttpAuthBuilder setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    public JcaHttpAuthBuilder setNonceGenerator(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public HttpAuth build()
        throws OperatorCreationException
    {
         return new HttpAuth(realm, username, password, random, new JcaDigestCalculatorProviderBuilder().build());
    }
}
