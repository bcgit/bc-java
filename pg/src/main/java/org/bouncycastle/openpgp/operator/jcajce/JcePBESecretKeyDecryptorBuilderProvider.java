package org.bouncycastle.openpgp.operator.jcajce;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptorBuilderProvider;

public class JcePBESecretKeyDecryptorBuilderProvider
        implements PBESecretKeyDecryptorBuilderProvider
{
    private final JcaPGPDigestCalculatorProviderBuilder digestCalculatorProviderBuilder;

    public JcePBESecretKeyDecryptorBuilderProvider(JcaPGPDigestCalculatorProviderBuilder digestCalculatorProviderBuilder)
    {
        this.digestCalculatorProviderBuilder = digestCalculatorProviderBuilder;
    }

    @Override
    public PBESecretKeyDecryptorBuilder provide()
            throws PGPException
    {
        return new JcePBESecretKeyDecryptorBuilder(digestCalculatorProviderBuilder.build());
    }
}
