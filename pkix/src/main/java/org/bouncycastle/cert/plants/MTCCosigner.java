package org.bouncycastle.cert.plants;

import java.io.IOException;

/**
 * Operator interface for producing a cosigner signature over the subtree
 * {@code [start, end)} of an MTC issuance log, per Section 5.3 of
 * draft-ietf-plants-merkle-tree-certs. Implementations encode the
 * {@link MTCCosignedMessage}, drive a signer bound to the cosigner's
 * private key at construction, and return the result already packaged as
 * an {@link MTCSignature} carrying the cosigner's trust anchor ID.
 *
 * <p>JCA-free and lightweight-crypto-free. Concrete bindings:
 * {@code org.bouncycastle.cert.plants.bc.BcMTCCosigner} (lightweight) and
 * {@code org.bouncycastle.cert.plants.jcajce.JcaMTCCosigner} (JCA).</p>
 */
public interface MTCCosigner
{
    /**
     * @return the binary trust anchor ID of this cosigner — the value that
     *         appears in {@link MTCSignature#getCosignerId()} on every
     *         signature produced by this instance. Per Section 5.3 of the
     *         draft, when the CA itself is acting as a cosigner this is the
     *         CA's own trust anchor ID.
     */
    byte[] getCosignerId();

    /**
     * Cosigns the subtree {@code [log.getStart(), log.getEnd())} of the
     * issuance log identified by {@code log.getLogId()}.
     *
     * @throws IOException if the CosignedMessage cannot be encoded or the
     *                     underlying signing operation fails
     */
    MTCSignature cosignSubtree(MTCLog log, byte[] subtreeHash)
        throws IOException;
}
