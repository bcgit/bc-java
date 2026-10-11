package org.bouncycastle.asn1.plants;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * OID constants for Merkle Tree Certificates (draft-ietf-plants-merkle-tree-certs).
 *
 * <p>These are the production values allocated in draft-07 under the PKIX
 * arcs (Section 13.1 of the draft). The interim placeholders under Cloudflare's
 * IANA PEN that earlier drafts used for experimentation have been removed and
 * are not aliased.</p>
 */
public interface MTCObjectIdentifiers
{
    /** id-pkix OID: 1.3.6.1.5.5.7 */
    ASN1ObjectIdentifier id_pkix = new ASN1ObjectIdentifier("1.3.6.1.5.5.7");

    /**
     * id-alg-mtcProof, the signatureAlgorithm of a Merkle Tree Certificate
     * (Section 6.2 of the draft): 1.3.6.1.5.5.7.6.67.
     */
    ASN1ObjectIdentifier id_alg_mtcProof = id_pkix.branch("6.67");

    /**
     * id-rdna-trustAnchorID, the RDN attribute carrying a CA ID as a
     * RELATIVE-OID in the issuer and subject fields (Section 5.1 of the
     * draft): 1.3.6.1.5.5.7.25.3.
     */
    ASN1ObjectIdentifier id_rdna_trustAnchorID = id_pkix.branch("25.3");

    /**
     * id-pe-mtcCertificationAuthority-SHA256, the CA certificate extension
     * for a Merkle Tree CA whose issuance logs hash with SHA-256 (Section 5.5
     * of the draft): 1.3.6.1.5.5.7.1.38. The hash function is identified by the
     * extension type; other hash functions would be given their own extension
     * OID.
     */
    ASN1ObjectIdentifier id_pe_mtcCertificationAuthority_SHA256 = id_pkix.branch("1.38");
}
