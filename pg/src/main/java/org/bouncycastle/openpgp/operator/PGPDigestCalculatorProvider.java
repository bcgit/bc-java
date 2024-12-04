package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;

/**
 * A factory for digest algorithms.
 * The purpose of this class is to act as an abstract factory, whose subclasses can decide, which concrete
 * implementation to use for calculating PGP digests.
 */
public interface PGPDigestCalculatorProvider
{
    /**
     * Construct a new instance of a cryptographic digest.
     * 
     * @param algorithm the identifier of the {@link HashAlgorithmTags digest algorithm} to
     *            instantiate.
     * @return a digest calculator for the specified algorithm.
     * @throws PGPException if an error occurs constructing the specified digest.
     */
    PGPDigestCalculator get(int algorithm)
        throws PGPException;
}
