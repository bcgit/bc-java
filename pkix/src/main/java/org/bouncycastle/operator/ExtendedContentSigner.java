package org.bouncycastle.operator;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * A Content Signer which also provides details of the digest algorithm used internally.
 */
public interface ExtendedContentSigner
    extends ContentSigner
{
    /**
     * Return the algorithm identifier describing the digest algorithm used by
     * this signature algorithm and parameters this signer generates.
     *
     * @return algorithm oid and parameters, null if unknown.
     */
    AlgorithmIdentifier getDigestAlgorithmIdentifier();
}
