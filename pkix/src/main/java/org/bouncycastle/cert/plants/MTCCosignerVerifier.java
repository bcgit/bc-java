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
}
