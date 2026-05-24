package org.bouncycastle.cert.plants;

/**
 * Operator interface for verifying a single cosigner signature over a
 * pre-encoded CosignedMessage, per Section 5.3.1 of
 * draft-ietf-plants-merkle-tree-certs.
 *
 * <p>An implementation is bound to a specific public key and algorithm at
 * construction; callers feed it the CosignedMessage bytes (built via
 * {@link MTCCosignedMessage#encode}) and the candidate signature, and the
 * implementation returns whether the signature is valid.</p>
 *
 * <p>JCA-free and lightweight-crypto-free. Concrete bindings:
 * {@code org.bouncycastle.cert.plants.bc.BcMTCSignatureVerifier} (lightweight)
 * and
 * {@code org.bouncycastle.cert.plants.jcajce.JcaMTCSignatureVerifier} (JCA).</p>
 */
public interface MTCSignatureVerifier
{
    /**
     * @param cosignedMessage the encoded CosignedMessage bytes
     * @param signature       the candidate signature
     * @return true if the signature is valid for the bound public key and algorithm
     */
    boolean verify(byte[] cosignedMessage, byte[] signature);
}
