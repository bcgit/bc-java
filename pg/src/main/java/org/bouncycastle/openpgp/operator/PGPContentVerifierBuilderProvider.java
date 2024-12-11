package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPException;

/**
 * Provider for {@link PGPContentVerifierBuilder} instances.
 * The purpose of this class is to act as an abstract factory, whose subclasses can decide, which concrete
 * implementation of {@link PGPContentVerifierBuilder} (builder for objects check signatures for correctness)
 * to provide.
 */
public interface PGPContentVerifierBuilderProvider
{
    PGPContentVerifierBuilder get(int keyAlgorithm, int hashAlgorithm)
        throws PGPException;
}
