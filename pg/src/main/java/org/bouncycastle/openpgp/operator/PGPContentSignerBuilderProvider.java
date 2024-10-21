package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPPublicKey;

/**
 * Provider class for {@link PGPContentSignerBuilder} instances.
 * Concrete implementations of this class can choose the cryptographic backend (BC, JCA/JCE).
 */
public abstract class PGPContentSignerBuilderProvider
{
    protected final int hashAlgorithmId;

    /**
     * Constructor.
     *
     * @param hashAlgorithmId ID of the hash algorithm the {@link PGPContentSignerBuilder} shall use.
     */
    public PGPContentSignerBuilderProvider(int hashAlgorithmId)
    {
        this.hashAlgorithmId = hashAlgorithmId;
    }

    /**
     * Return a new instance of the {@link PGPContentSignerBuilder} for the given signing key.
     * @param signingKey public part of the signing key
     * @return content signer builder
     */
    public abstract PGPContentSignerBuilder get(PGPPublicKey signingKey);
}
