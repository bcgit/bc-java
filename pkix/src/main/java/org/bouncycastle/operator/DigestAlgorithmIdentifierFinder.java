package org.bouncycastle.operator;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface DigestAlgorithmIdentifierFinder
    extends AlgorithmIdentifierFinder
{
    /**
     * Find the digest algorithm identifier that matches with
     * the passed in signature algorithm identifier.
     *
     * @param sigAlgId the signature algorithm of interest.
     * @return an algorithm identifier for the corresponding digest, null if the signature
     *         algorithm does not identify one.
     */
    AlgorithmIdentifier find(AlgorithmIdentifier sigAlgId);

    /**
     * Find the algorithm identifier that matches with
     * the passed in digest OID.
     *
     * @param digestOid the OID of the digest algorithm of interest.
     * @return an algorithm identifier for the digest signature.
     */
    AlgorithmIdentifier find(ASN1ObjectIdentifier digestOid);

    /**
     * Find the algorithm identifier that matches with
     * the passed in digest name. The name may also be given in dotted OID form.
     *
     * @param digAlgName the name of the digest algorithm of interest.
     * @return an algorithm identifier for the digest signature.
     * @throws IllegalArgumentException if the name is not recognised.
     */
    AlgorithmIdentifier find(String digAlgName);
}