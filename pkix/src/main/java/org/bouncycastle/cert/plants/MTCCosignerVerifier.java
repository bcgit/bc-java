package org.bouncycastle.cert.plants;

import org.bouncycastle.operator.ContentVerifier;

/**
 * Operator that verifies a single cosigner's signature over a CosignedMessage
 * as defined by Section 5.3.1 of
 * <a href="https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/">draft-ietf-plants-merkle-tree-certs</a>.
 *
 * <p>Implementations encapsulate the cosigner's public key and the algorithm
 * choice. As a {@link ContentVerifier}, callers feed the already-encoded
 * CosignedMessage bytes (e.g. via {@link MTCCosignedMessage#encode}) through
 * {@link #getOutputStream()} and then call {@link #verify(byte[])} with the
 * candidate signature.</p>
 *
 * @see MTCCosignerVerifierProvider
 * @see MTCCosignedMessage
 */
public interface MTCCosignerVerifier
    extends ContentVerifier
{
    /**
     * @return the binary trust anchor ID of the cosigner this verifier is
     *         bound to — the key under which it was registered with its
     *         {@link MTCCosignerVerifierProvider}. Consumers counting
     *         cosignatures use this to confirm a signature's
     *         {@code cosigner_id} names the identity of the key it is checked
     *         against, rather than relying solely on the {@code cosigner_name}
     *         binding inside the CosignedMessage.
     */
    byte[] getCosignerId();
}
