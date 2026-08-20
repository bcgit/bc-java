package org.bouncycastle.operator;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface KemEncapsulationLengthProvider
{
    /**
     * Return the length, in bytes, of the encapsulation produced by the passed in KEM algorithm.
     *
     * @param kemAlgorithm the algorithm identifier of the KEM of interest.
     * @return the encapsulation length in bytes.
     * @throws IllegalArgumentException if the KEM algorithm is not recognised.
     */
    int getEncapsulationLength(AlgorithmIdentifier kemAlgorithm);
}
