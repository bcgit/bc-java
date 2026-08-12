package org.bouncycastle.operator;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Base interface for the finders that turn an algorithm name into the
 * {@link AlgorithmIdentifier} - algorithm OID plus any algorithm-specific
 * parameters - that names it in an ASN.1 structure.
 * <p>
 * Implemented by {@link SignatureAlgorithmIdentifierFinder},
 * {@link KemAlgorithmIdentifierFinder} and {@link DigestAlgorithmIdentifierFinder},
 * whose finders match names without regard to case and throw
 * {@link IllegalArgumentException} for a name they do not recognise rather than
 * returning null.
 * </p><p>
 * Two things this contract does not reach. {@link MacAlgorithmIdentifierFinder}
 * stands outside the hierarchy entirely, as it returns null for an unrecognised
 * name; and the digest finder's further overloads keep their own behaviour - it
 * also reads a name given in dotted OID form, and its
 * {@code find(AlgorithmIdentifier)} returns null when it cannot derive a digest
 * from a signature algorithm.
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
