package org.bouncycastle.tls.crypto;

import java.io.IOException;

/**
 * Interface supporting the generation of key material and other SSL/TLS secret values from PRFs.
 */
public interface TlsSecret
{
    /**
     * Calculate an HMAC with this secret's data as the key.
     * 
     * @param cryptoHashAlgorithm
     *            the hash algorithm to instantiate HMAC with. See {@link CryptoHashAlgorithm} for values.
     * @param buf array containing the input data.
     * @param off offset into the input array the input starts at.
     * @param len the length of the input data.
     * @return
     */
    byte[] calculateHMAC(int cryptoHashAlgorithm, byte[] buf, int off, int len);

    /**
     * Return a new secret based on applying a PRF to this one.
     *
     * @param prfAlgorithm PRF algorithm to use.
     * @param label the label details.
     * @param seed the seed details.
     * @param length the size (in bytes) of the secret to generate.
     * @return the new secret.
     */
    TlsSecret deriveUsingPRF(int prfAlgorithm, String label, byte[] seed, int length);

    /**
     * Destroy the internal state of the secret. After this call, any attempt to use the
     * {@link TlsSecret} will result in an {@link IllegalStateException} being thrown.
     */
    void destroy();

    /**
     * Return an encrypted copy of the data this secret is based on.
     *
     * @param encryptor the encryptor to use for protecting the internal data.
     * @return an encrypted copy of this secret's internal data.
     */
    byte[] encrypt(TlsEncryptor encryptor) throws IOException;

    /**
     * Return the internal data from this secret. The {@link TlsSecret} does not keep a copy of the
     * data. After this call, any attempt to use the {@link TlsSecret} will result in an
     * {@link IllegalStateException} being thrown.
     *
     * @return the secret's internal data.
     */
    byte[] extract();

    /**
     * RFC 5869 HKDF-Expand function, with this secret's data as the pseudo-random key ('prk').
     * 
     * @param cryptoHashAlgorithm
     *            the hash algorithm to instantiate HMAC with. See {@link CryptoHashAlgorithm} for values.
     * @param info
     *            optional context and application specific information (can be zero-length).
     * @param length
     *            length of output keying material in octets.
     * @return output keying material (of 'length' octets).
     */
    TlsSecret hkdfExpand(int cryptoHashAlgorithm, byte[] info, int length);

    /**
     * RFC 5869 HKDF-Extract function, with this secret's data as the 'salt'. The {@link TlsSecret}
     * does not keep a copy of the data. After this call, any attempt to use the {@link TlsSecret}
     * will result in an {@link IllegalStateException} being thrown.
     * 
     * @param cryptoHashAlgorithm
     *            the hash algorithm to instantiate HMAC with. See {@link CryptoHashAlgorithm} for values.
     * @param ikm
     *            input keying material.
     * @return a pseudo-random key (of HashLen octets).
     */
    TlsSecret hkdfExtract(int cryptoHashAlgorithm, TlsSecret ikm);

    boolean isAlive();
}
