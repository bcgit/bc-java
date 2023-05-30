package org.bouncycastle.openpgp;

/**
 * Base interface for thread safe signature verified objects.
 */
public interface PGPSignatureVerifier
{
    /**
     * Return the signature type.
     *
     * @return signature type.
     */
    int getSignatureType();

    /**
     * Return if the signature verifies or not.
     *
     * @return true if verifies, false otherwise.
     * @throws PGPException on signature processing failure.
     */
    boolean isVerified()
        throws PGPException;
}
