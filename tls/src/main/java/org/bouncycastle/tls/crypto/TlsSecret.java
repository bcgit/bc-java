package org.bouncycastle.tls.crypto;

import java.io.IOException;

/**
 * Interface supporting the generation of key material and other SSL/TLS secret values from PRFs.
 */
public interface TlsSecret
{
    /**
     * Derive a new SSL key block using the passed in seed.
     *
     * @param seed the joint random value.
     * @param length the length (in bytes) required.
     * @return the newly derived secret.
     */
    TlsSecret deriveSSLKeyBlock(byte[] seed, int length);

    /**
     * Derive a new SSL master secret using the passed in seed.
     *
     * @param seed the session hash or joint random value.
     * @return the newly derived secret.
     */
    TlsSecret deriveSSLMasterSecret(byte[] seed);

    /**
     * Return a new secret based on applying a PRF to this one.
     *
     * @param prfAlgorithm PRF algorithm to use.
     * @param labelSeed the appropriate concatenation of the label and seed details
     * @param length the size (in bytes) of the secret to generate.
     * @return the new secret.
     */
    TlsSecret deriveUsingPRF(int prfAlgorithm, byte[] labelSeed, int length);

    /**
     * Return the a copy of the data this secret is based on.
     *
     * @return the secret's internal data.
     */
    byte[] extract();

    /**
     * Return the an encrypted copy of the data this secret is based on.
     *
     * @param encryptor the encryptor to use for protecting the internal data.
     * @return an encrypted copy of secret's internal data.
     */
    byte[] copy(TlsEncryptor encryptor) throws IOException;

    /**
     * Destroy the internal state of the secret.
     */
    void destroy();
}
