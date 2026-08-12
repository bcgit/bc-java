package org.bouncycastle.operator;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Base interface for the finders that turn an algorithm name into the
 * {@link AlgorithmIdentifier} - algorithm OID plus any algorithm-specific
 * parameters - that names it in an ASN.1 structure.
 * <p>
 * What happens for a name the finder does not recognise is left to the
 * implementation, and the existing ones differ: the signature and KEM finders
 * throw {@link IllegalArgumentException}, while the digest and MAC finders
 * return null. So do not assume either without checking the implementation you
 * are holding. Name matching is likewise implementation-specific - most fold
 * case, {@link DefaultDigestAlgorithmIdentifierFinder} does not.
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
     */
    AlgorithmIdentifier find(String algorithmName);
}
