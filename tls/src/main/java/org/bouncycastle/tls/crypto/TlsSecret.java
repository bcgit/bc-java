package org.bouncycastle.tls.crypto;

import java.io.IOException;

public interface TlsSecret
{
    TlsSecret deriveSSLKeyBlock(byte[] seed, int length);

    TlsSecret deriveSSLMasterSecret(byte[] seed);

    TlsSecret prf(int prfAlgorithm, byte[] labelSeed, int length);

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
