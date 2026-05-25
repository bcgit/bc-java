package org.bouncycastle.cert.plants;

/**
 * Constants for the {@code MerkleTreeCertEntryType} enum defined in
 * Section 5.2.1 of draft-ietf-plants-merkle-tree-certs:
 *
 * <pre>
 * enum {
 *     null_entry(0), tbs_cert_entry(1), (2^16-1)
 * } MerkleTreeCertEntryType;
 * </pre>
 *
 * <p>The on-wire encoding is a big-endian uint16. Future drafts may define
 * additional values.</p>
 */
public final class MerkleTreeCertEntryType
{
    /** {@code null_entry} — a no-information placeholder entry. */
    public static final int NULL_ENTRY = 0;

    /** {@code tbs_cert_entry} — the body is a DER-encoded TBSCertificateLogEntry contents. */
    public static final int TBS_CERT_ENTRY = 1;

    private MerkleTreeCertEntryType()
    {
    }
}
