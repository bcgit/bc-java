package org.bouncycastle.cert.plants;

import org.bouncycastle.util.Arrays;

/**
 * A single cosigner signature, as it appears inside the TLS-encoded MTCProof
 * defined by
 * <a href="https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/#section-6.1">draft-ietf-plants-merkle-tree-certs, Section 6.1</a>:
 *
 * <pre>
 * struct {
 *     TrustAnchorID cosigner_id;
 *     opaque signature&lt;0..2^16-1&gt;;
 * } MTCSignature;
 *
 * opaque TrustAnchorID&lt;1..2^8-1&gt;;
 * </pre>
 *
 * <p>The cosigner ID is the <em>binary</em> trust anchor ID per Section 3 of
 * draft-ietf-tls-trust-anchor-ids &mdash; the base-128 OID-component bytes
 * only, without the ASN.1 RELATIVE-OID tag or length octets. See
 * {@link TrustAnchorIDs} for converting to/from the dotted-decimal form.</p>
 */
public class MTCSignature
{
    private final byte[] cosignerId;
    private final byte[] signature;

    /**
     * @param cosignerId binary trust anchor ID (1..255 bytes)
     * @param signature  raw signature value (0..65535 bytes)
     */
    public MTCSignature(byte[] cosignerId, byte[] signature)
    {
        if (cosignerId == null || cosignerId.length < 1 || cosignerId.length > 255)
        {
            throw new IllegalArgumentException("cosigner_id length must be 1..255 bytes");
        }
        if (signature == null || signature.length > 0xFFFF)
        {
            throw new IllegalArgumentException("signature length must be 0..65535 bytes");
        }
        this.cosignerId = Arrays.clone(cosignerId);
        this.signature = Arrays.clone(signature);
    }

    /**
     * @return the binary trust anchor ID of the cosigner
     */
    public byte[] getCosignerId()
    {
        return Arrays.clone(cosignerId);
    }

    /**
     * @return the raw signature value
     */
    public byte[] getSignature()
    {
        return Arrays.clone(signature);
    }
}
