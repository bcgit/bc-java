package org.bouncycastle.operator;

/**
 * Extension of {@link OutputEncryptor} for encryptors that can predict the
 * exact ciphertext length produced for a given plaintext length. This enables
 * definite-length (DL/DER) streaming of CMS structures: the encrypted-content
 * OCTET STRING's length has to be written before any ciphertext flows, so the
 * producer needs the count up front.
 *
 * <p>For encryptors that do not implement this interface the CMS stream
 * generators fall back to deriving the count from the encryptor's
 * {@link OutputEncryptor#getAlgorithmIdentifier() algorithm identifier} where
 * the algorithm is recognised; implement this interface to support
 * definite-length output with algorithms outside that set.</p>
 */
public interface KnownLengthOutputEncryptor
    extends OutputEncryptor
{
    /**
     * Return the exact number of ciphertext octets that encrypting
     * {@code inputLength} plaintext octets will produce, including any
     * appended AEAD tag where the CMS structure carries the tag inside the
     * encrypted content.
     *
     * @param inputLength number of plaintext octets to be encrypted
     * @return the exact ciphertext octet count, or -1 if it cannot be determined
     */
    long getOutputLength(long inputLength);
}
