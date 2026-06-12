package org.bouncycastle.operator;

/**
 * Extension of {@link ContentSigner} for signers whose signature encoding has
 * a fixed, predictable length — RSA (PKCS#1 v1.5 and PSS: the modulus size),
 * Ed25519/Ed448 and ML-DSA qualify; DER-encoded ECDSA/DSA do not (the
 * INTEGER components vary in length).
 *
 * <p>This enables definite-length (DL/DER) streaming of CMS SignedData with
 * encapsulated content: the SignerInfos trail the content in the encoding but
 * their length feeds the enclosing headers, which are written before any
 * content flows — so the signature length has to be committed up front.</p>
 */
public interface FixedLengthContentSigner
    extends ContentSigner
{
    /**
     * Return the exact length in octets of the signature this signer will
     * produce.
     *
     * @return the signature length, or -1 if it cannot be fixed in advance
     */
    int getSignatureLength();
}
