package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.tls.SignatureAndHashAlgorithm;

/**
 * Base interface for a TLS signer that works on raw message digests.
 */
public interface TlsSigner
{
    /**
     * Generate an encoded signature based on the passed in hash,
     *
     * @param algorithm the signature algorithm to use.
     * @param hash the hash calculated for the signature.
     * @return an encoded signature.
     * @throws IOException in case of an exception processing the hash.
     */
    byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash)
        throws IOException;

    TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) throws IOException;
}
