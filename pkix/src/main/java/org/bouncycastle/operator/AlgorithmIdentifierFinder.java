package org.bouncycastle.operator;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Base interface for the finders that turn an algorithm name into the
 * {@link AlgorithmIdentifier} - algorithm OID plus any algorithm-specific
 * parameters - naming it in an ASN.1 structure.
 * <p>
 * Implementations match names without regard to case, and throw
 * {@link IllegalArgumentException} for a name they do not recognise rather than
 * returning null. {@link MacAlgorithmIdentifierFinder} returns null instead, and
 * so is deliberately not part of this hierarchy.
 * </p>
 */
public interface AlgorithmIdentifierFinder
{
    /**
     * Find the algorithm identifier that matches with
     * the passed in algorithm name.
     *
     * @param algorithmName the name of the algorithm of interest.
     * @return an algorithm identifier for the corresponding algorithm.
     * @throws IllegalArgumentException if the name is not recognised.
     */
    AlgorithmIdentifier find(String algorithmName);
}
