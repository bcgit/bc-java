package org.bouncycastle.cert.plants;

import org.bouncycastle.operator.ContentVerifier;

/**
 * Operator interface for verifying a single cosigner signature over a
 * pre-encoded CosignedMessage, per Section 5.3.1 of
 * draft-ietf-plants-merkle-tree-certs.
 *
 * <p>An implementation is bound to a specific public key and algorithm at
 * construction. As an {@link ContentVerifier}, callers feed the CosignedMessage
 * bytes (built via {@link MTCCosignedMessage#encode}) through
 * {@link #getOutputStream()} and then call {@link #verify(byte[])} with the
 * candidate signature to check.</p>
 *
 * <p>JCA-free and lightweight-crypto-free. Concrete bindings:
 * {@code org.bouncycastle.cert.plants.bc.BcMTCSignatureVerifier} (lightweight)
 * and
 * {@code org.bouncycastle.cert.plants.jcajce.JcaMTCSignatureVerifier} (JCA).</p>
 */
public interface MTCSignatureVerifier
    extends ContentVerifier
{
}
