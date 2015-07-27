package org.bouncycastle.operator;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * General finder for converting OIDs and AlgorithmIdentifiers into strings.
 */
public interface AlgorithmNameFinder
{
    /**
     * Return true if the passed in objectIdentifier has a "human friendly" name associated with it.
     *
     * @param objectIdentifier the OID of interest.
     * @return true if a name lookup exists for the OID, false otherwise.
     */
    boolean hasAlgorithmName(ASN1ObjectIdentifier objectIdentifier);

    /**
     * Return a string representation of the passed in objectIdentifier.
     *
     * @param objectIdentifier the OID of interest.
     * @return a "human friendly" representation of the OID, the OID as a string if none available.
     */
    String getAlgorithmName(ASN1ObjectIdentifier objectIdentifier);

    /**
     * Return a string representation of the passed in AlgorithmIdentifier, based on the OID in the AlgorithmField, with the parameters
     * included where appropriate.
     *
     * @param algorithmIdentifier the AlgorithmIdentifier of interest.
     * @return a "human friendly" representation of the algorithmIdentifier, the identifiers OID as a string if none available.
     */
    String getAlgorithmName(AlgorithmIdentifier algorithmIdentifier);
}
