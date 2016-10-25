package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.tls.DigitallySigned;

/**
 * Base interface for a TLS verfier that works with signatures and raw message digests.
 */
public interface TlsVerifier
{
    /**
     * Return true if the passed in signature and hash represent a real signature.
     *
     * @param signature the signature object containg the signature to be verified.
     * @param hash the hash calculated for the signature.
     * @return true if signature verifies, false otherwise.
     * @throws IOException in case of an exception verifying signature.
     */
    boolean verifySignature(DigitallySigned signature, byte[] hash) throws IOException;
}
