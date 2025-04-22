package org.bouncycastle.openpgp.operator.jcajce;

import java.security.Provider;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptorBuilderProvider;

public class JcePBESecretKeyDecryptorBuilderProvider
        implements PBESecretKeyDecryptorBuilderProvider
{
    private final JcaPGPDigestCalculatorProviderBuilder digestCalculatorProviderBuilder;
    private Provider provider;

    public JcePBESecretKeyDecryptorBuilderProvider(JcaPGPDigestCalculatorProviderBuilder digestCalculatorProviderBuilder)
    {
        this.digestCalculatorProviderBuilder = digestCalculatorProviderBuilder;
    }

    public JcePBESecretKeyDecryptorBuilderProvider setProvider(Provider provider)
    {
        this.provider = provider;
        return this;
    }

    @Override
    public PBESecretKeyDecryptorBuilder provide()
            throws PGPException
    {
        JcePBESecretKeyDecryptorBuilder b = new JcePBESecretKeyDecryptorBuilder(digestCalculatorProviderBuilder.build());
        if (provider != null)
        {
            b.setProvider(provider);
        }
        return b;
    }
}
