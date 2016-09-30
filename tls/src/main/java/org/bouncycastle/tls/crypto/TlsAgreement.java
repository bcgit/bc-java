package org.bouncycastle.tls.crypto;

import java.io.IOException;

/**
 * Base interface for ephemeral key agreement calculator.
 */
public interface TlsAgreement
{
    /**
     * Generate an ephemeral key pair, returning the encoding of the public key.
     *
     * @return a byte encoding of the public key.
     * @throws IOException in case of error.
     */
    byte[] generateEphemeral() throws IOException;

    /**
     * Pass in the public key for the peer to the agreement calculator.
     *
     * @param peerValue a byte encoding of the peer public key.
     * @throws IOException in case of error.
     */
    void receivePeerValue(byte[] peerValue) throws IOException;

    /**
     * Calculate the agreed secret based on the calculator's current state.
     * @return the calculated secret.
     * @throws IOException in case of error.
     */
    TlsSecret calculateSecret() throws IOException;
}
