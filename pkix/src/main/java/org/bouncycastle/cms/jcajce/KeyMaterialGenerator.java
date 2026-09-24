package org.bouncycastle.cms.jcajce;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

interface KeyMaterialGenerator
{
    /**
     * Generate the KDF "other info" material for a key agreement, typically a DER-encoded
     * ECC-CMS-SharedInfo (RFC 5753).
     *
     * @param keyAlgorithm the algorithm identifier of the key being derived (the key wrap algorithm);
     * an implementation may bind this into the material, or ignore it.
     * @param keySize the size of the key being derived, in bits; an implementation may bind this into
     * the material, or ignore it. It does not determine the length of the derived key.
     * @param userKeyMaterialParameters the user keying material (ukm) from the message, or null if there is none.
     * @return the KDF material, or null if there is none. An implementation may return
     * userKeyMaterialParameters itself rather than a copy, which calling code should take into
     * consideration in determining ownership of the result.
     */
    byte[] generateKDFMaterial(AlgorithmIdentifier keyAlgorithm, int keySize, byte[] userKeyMaterialParameters);
}
