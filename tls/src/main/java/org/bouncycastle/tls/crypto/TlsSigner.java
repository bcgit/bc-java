package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsContext;

/**
 * Base interface for a TLS signer that works on raw message digests.
 */
public interface TlsSigner
{
    /**
     * Return the TLS context associated with this service.
     *
     * @return the context for this service.
     */
    TlsContext getContext();

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
}
