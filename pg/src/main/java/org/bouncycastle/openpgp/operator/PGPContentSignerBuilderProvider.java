package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPPublicKey;

public abstract class PGPContentSignerBuilderProvider
{
    protected final int hashAlgorithmId;

    public PGPContentSignerBuilderProvider(int hashAlgorithmId)
    {
        this.hashAlgorithmId = hashAlgorithmId;
    }

    public abstract PGPContentSignerBuilder get(PGPPublicKey signingKey);
}
