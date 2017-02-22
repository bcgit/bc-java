package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsStreamSigner;

/**
 * Support interface for generating a signature based on our private credentials.
 */
public interface TlsCredentialedSigner
    extends TlsCredentials
{
    /**
     * Generate a signature against the passed in hash.
     *
     * @param hash a message digest calculated across the message the signature is to apply to.
     * @return an encoded signature.
     * @throws IOException if the hash cannot be processed, or there is an issue with the private credentials.
     */
    byte[] generateRawSignature(byte[] hash)
        throws IOException;

    /**
     * Return the algorithm IDs for the signature algorithm and the associated hash it uses.
     *
     * @return the full algorithm details for the signature.
     */
    SignatureAndHashAlgorithm getSignatureAndHashAlgorithm();

    TlsStreamSigner getStreamSigner() throws IOException;
}
