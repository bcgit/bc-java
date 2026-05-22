package org.bouncycastle.cert.plants;

import java.io.IOException;

/**
 * Operator that verifies a single cosigner's signature over a CosignedMessage
 * as defined by Section 5.3.1 of
 * <a href="https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/">draft-ietf-plants-merkle-tree-certs</a>.
 *
 * <p>Implementations encapsulate the cosigner's public key and the algorithm
 * choice; the caller supplies the already-encoded CosignedMessage bytes (e.g.
 * via {@link MTCCosignedMessage#encode}) together with the candidate signature.</p>
 *
 * @see MTCCosignerVerifierProvider
 * @see MTCCosignedMessage
 */
public interface MTCCosignerVerifier
{
    /**
     * Verify that {@code signature} is a valid signature over {@code cosignedMessage}
     * by the cosigner this verifier was constructed for.
     *
     * @param cosignedMessage the encoded CosignedMessage bytes
     * @param signature       the candidate signature
     * @return {@code true} iff the signature verifies
     */
    boolean verify(byte[] cosignedMessage, byte[] signature)
        throws IOException;
}
