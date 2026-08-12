package org.bouncycastle.operator;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Base interface for the finders that turn an algorithm name into the
 * {@link AlgorithmIdentifier} - algorithm OID plus any algorithm-specific
 * parameters - that names it in an ASN.1 structure.
 * <p>
 * Implemented by {@link SignatureAlgorithmIdentifierFinder} and
 * {@link KemAlgorithmIdentifierFinder}, whose finders match names without regard
 * to case and throw {@link IllegalArgumentException} for a name they do not
 * recognise rather than returning null.
 * </p><p>
 * The digest and MAC finders deliberately stand outside this hierarchy: they
 * return null for an unrecognised name, and {@code DigestAlgorithmIdentifierFinder}
 * additionally reads a name given in dotted OID form, so neither shares the
 * contract above.
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
