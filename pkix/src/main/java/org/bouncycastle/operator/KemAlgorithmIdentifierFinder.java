package org.bouncycastle.operator;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Finder for the {@link AlgorithmIdentifier} naming a key encapsulation
 * mechanism, as it appears in a SubjectPublicKeyInfo, a CMS KEMRecipientInfo
 * (RFC 9629) or a CMP KemCiphertextInfo.
 * <p>
 * This is the KEM counterpart of {@link SignatureAlgorithmIdentifierFinder}.
 * The reverse direction - naming an OID that arrived from a peer - is
 * {@link DefaultAlgorithmNameFinder}.
 * </p>
 */
public interface KemAlgorithmIdentifierFinder
    extends AlgorithmIdentifierFinder
{
    /**
     * Return true if a KEM algorithm of the passed in name is recognised, false
     * otherwise. Where this returns true {@link #find(String)} returns an
     * identifier; where it returns false {@code find} throws, so this is the way
     * to test for support without catching.
     *
     * @param kemAlgName the name of the KEM algorithm of interest.
     * @return true if the name is recognised, false otherwise.
     */
    boolean hasAlgorithm(String kemAlgName);

    /**
     * Find the KEM algorithm identifier that matches with
     * the passed in KEM algorithm name.
     *
     * @param kemAlgName the name of the KEM algorithm of interest.
     * @return an algorithm identifier for the corresponding KEM.
     * @throws IllegalArgumentException if the name is not recognised.
     */
    AlgorithmIdentifier find(String kemAlgName);
}
