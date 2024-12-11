package org.bouncycastle.openpgp.operator.jcajce;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilderProvider;

import java.security.Provider;
import java.security.SecureRandom;

public class JcaPGPContentSignerBuilderProvider
        extends PGPContentSignerBuilderProvider
{
    private Provider digestProvider;
    private Provider securityProvider;
    private SecureRandom secureRandom;

    public JcaPGPContentSignerBuilderProvider(int hashAlgorithmId)
    {
        super(hashAlgorithmId);
    }

    public JcaPGPContentSignerBuilderProvider setDigestProvider(Provider provider)
    {
        this.digestProvider = provider;
        return this;
    }

    public JcaPGPContentSignerBuilderProvider setSecurityProvider(Provider provider)
    {
        this.securityProvider = provider;
        return this;
    }

    public JcaPGPContentSignerBuilderProvider setSecureRandom(SecureRandom random)
    {
        this.secureRandom = random;
        return this;
    }

    @Override
    public PGPContentSignerBuilder get(PGPPublicKey signingKey)
    {
        JcaPGPContentSignerBuilder builder = new JcaPGPContentSignerBuilder(
                signingKey.getAlgorithm(), hashAlgorithmId);
        if (digestProvider != null)
        {
            builder.setDigestProvider(digestProvider);
        }

        if (securityProvider != null)
        {
            builder.setProvider(securityProvider);
        }

        if (secureRandom != null)
        {
            builder.setSecureRandom(secureRandom);
        }
        return builder;
    }
}
