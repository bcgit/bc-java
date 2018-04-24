package org.bouncycastle.tls.crypto;

public interface TlsNonceGenerator
{
    /**
     * Generate a nonce byte[] string.
     *
     * @param size the length, in bytes, of the nonce to generate.
     * @return the nonce value.
     */
    byte[] generateNonce(int size);
}
