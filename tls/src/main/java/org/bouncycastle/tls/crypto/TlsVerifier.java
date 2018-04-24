package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.tls.DigitallySigned;

/**
 * Base interface for a TLS verifier that works with signatures and either raw message digests, or
 * entire messages.
 */
public interface TlsVerifier
{
    TlsStreamVerifier getStreamVerifier(DigitallySigned signature) throws IOException;

    /**
     * Return true if the passed in signature and hash represent a real signature.
     *
     * @param signature the signature object containing the signature to be verified.
     * @param hash the hash calculated for the signature.
     * @return true if signature verifies, false otherwise.
     * @throws IOException in case of an exception verifying signature.
     */
    boolean verifyRawSignature(DigitallySigned signature, byte[] hash) throws IOException;
}
