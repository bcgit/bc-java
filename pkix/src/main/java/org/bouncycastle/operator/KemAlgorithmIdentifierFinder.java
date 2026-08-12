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
     * Find the KEM algorithm identifier that matches with
     * the passed in KEM algorithm name.
     *
     * @param kemAlgName the name of the KEM algorithm of interest.
     * @return an algorithm identifier for the corresponding KEM.
     */
    AlgorithmIdentifier find(String kemAlgName);
}
