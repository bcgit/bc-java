package org.bouncycastle.openpgp.operator.bc;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilderProvider;

public class BcPGPContentSignerBuilderProvider
        extends PGPContentSignerBuilderProvider
{

    public BcPGPContentSignerBuilderProvider(int hashAlgorithmId)
    {
        super(hashAlgorithmId);
    }

    @Override
    public PGPContentSignerBuilder get(PGPPublicKey signingKey)
    {
        return new BcPGPContentSignerBuilder(signingKey.getAlgorithm(), hashAlgorithmId);
    }
}
