package org.bouncycastle.tls.crypto.jcajce;

import java.security.Provider;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

public class JcaTlsCryptoBuilder
{
    private JcaJceHelper helper = new DefaultJcaJceHelper();

    private static final Map algorithms = new HashMap();

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
        return new JcaTlsCrypto(helper);
    }
}
