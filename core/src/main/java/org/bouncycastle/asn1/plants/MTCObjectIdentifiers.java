package org.bouncycastle.asn1.plants;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * OID constants used by the experimental encoding of Merkle Tree Certificates
 * (draft-ietf-plants-merkle-tree-certs).
 *
 * <p>Section 5.2 and Section 6.1 of the draft reserve two arcs under
 * Cloudflare's IANA PEN (1.3.6.1.4.1.44363.47) for early implementations,
 * until IANA assigns the production OIDs under the PKIX algorithms (1.3.6.1.5.5.7.6)
 * and RDN attribute (1.3.6.1.5.5.7.25) arcs.</p>
 *
 * <p><b>To be deleted</b>: every constant in this class is an interim placeholder
 * under the Cloudflare PEN. When IANA assigns the production OIDs, these
 * constants should be removed and the production OIDs added (under a different
 * arc class) — no back-compat aliases.</p>
 */
public interface MTCObjectIdentifiers
{
    /** Cloudflare's IANA PEN arc. To be deleted when production OIDs are assigned. */
    ASN1ObjectIdentifier cloudFlare = new ASN1ObjectIdentifier("1.3.6.1.4.1.44363");

    /**
     * id-alg-mtcProof signature-algorithm OID for the certificate signatureAlgorithm field.
     * To be deleted when IANA assigns the production OID under id-pkix algorithms.
     */
    ASN1ObjectIdentifier id_alg_mtcProof = cloudFlare.branch("47.0");

    /**
     * id-rdna-trustAnchorID RDN attribute OID for the certificate issuer field.
     * To be deleted when IANA assigns the production OID under id-pkix RDN attributes.
     */
    ASN1ObjectIdentifier id_rdna_trustAnchorID = cloudFlare.branch("47.1");

    /**
     * id-pe-mtcCertificationAuthority extension OID for the CA certificate
     * representation (Section 5.5 of the draft). To be deleted when IANA assigns
     * the production OID.
     */
    ASN1ObjectIdentifier id_pe_mtcCertificationAuthority = cloudFlare.branch("47.2");
}
