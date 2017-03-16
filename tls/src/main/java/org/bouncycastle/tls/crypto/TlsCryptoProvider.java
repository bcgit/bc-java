package org.bouncycastle.tls.crypto;


import java.security.SecureRandom;

/**
 * Interface that provider's of TlsCrypto implementations need to conform to.
 */
public interface TlsCryptoProvider
{
    /**
     * Create a TlsCrypto using the passed in sources of entropy for key material and nonce generation.
     *
     * @param random SecureRandom for generating key material and seeds for nonce generation.
     * @return a TlsCrypto.
     */
    TlsCrypto create(SecureRandom random);

    /**
     * Create a TlsCrypto using the passed in sources of entropy for keys and nonces.
     *
     * @param keyRandom SecureRandom for generating key material.
     * @param nonceRandom SecureRandom for generating nonces.
     * @return a TlsCrypto.
     */
    TlsCrypto create(SecureRandom keyRandom, SecureRandom nonceRandom);
}
