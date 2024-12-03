package org.bouncycastle.openpgp.operator.bc;

import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptorBuilderProvider;

public class BcPBESecretKeyDecryptorBuilderProvider
        implements PBESecretKeyDecryptorBuilderProvider
{
    @Override
    public PBESecretKeyDecryptorBuilder provide()
    {
        return new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider());
    }
}
