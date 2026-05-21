package org.bouncycastle.cert.plants;

import org.bouncycastle.asn1.ASN1RelativeOID;

/**
 * Utilities for constructing and parsing the binary trust anchor IDs reserved
 * by Section 5.1 of draft-ietf-plants-merkle-tree-certs-04 under each CA ID:
 *
 * <ul>
 *   <li>{@code {caID 0 N}} &mdash; issuance log {@code N} (Section 5.2)</li>
 *   <li>{@code {caID 1 N L}} &mdash; landmark {@code L} of log {@code N} (Section 8.2)</li>
 *   <li>{@code {caID 2 N L}} &mdash; landmark group containing landmark {@code L}
 *       and earlier (Section 8.2.1)</li>
 * </ul>
 *
 * <p>The binary representation is the base-128 OID-component encoding used
 * inside ASN.1 RELATIVE-OID contents (Section 3 of draft-ietf-tls-trust-anchor-ids);
 * it has no ASN.1 tag or length prefix.</p>
 */
public final class TrustAnchorIDs
{
    /** OID component for the logs arc. */
    public static final int LOGS_ARC = 0;
    /** OID component for the landmarks arc (per-landmark IDs, Section 8.2). */
    public static final int LANDMARKS_ARC = 1;
    /** OID component for the landmark-groups arc (Section 8.2.1). */
    public static final int LANDMARK_GROUPS_ARC = 2;

    private TrustAnchorIDs()
    {
    }

    /**
     * Builds the binary trust anchor ID of an issuance log.
     *
     * @param caId      binary trust anchor ID of the CA
     * @param logNumber log number ({@code 1 <= logNumber <= 2^16-1}, Section 5.2)
     */
    public static byte[] logId(byte[] caId, long logNumber)
    {
        if (logNumber < 1 || logNumber > 0xFFFFL)
        {
            throw new IllegalArgumentException("log_number out of range [1, 65535]: " + logNumber);
        }
        return concat(caId, encodeComponent(LOGS_ARC), encodeComponent(logNumber));
    }

    /**
     * Builds the binary trust anchor ID of a landmark (Section 8.2).
     *
     * @param caId           binary trust anchor ID of the CA
     * @param logNumber      log number
     * @param landmarkNumber landmark number ({@code landmarkNumber >= 0})
     */
    public static byte[] landmarkId(byte[] caId, long logNumber, long landmarkNumber)
    {
        if (logNumber < 1 || logNumber > 0xFFFFL)
        {
            throw new IllegalArgumentException("log_number out of range: " + logNumber);
        }
        if (landmarkNumber < 0)
        {
            throw new IllegalArgumentException("landmark_number must be non-negative: " + landmarkNumber);
        }
        return concat(caId,
            encodeComponent(LANDMARKS_ARC),
            encodeComponent(logNumber),
            encodeComponent(landmarkNumber));
    }

    /**
     * Builds the binary trust anchor ID of a landmark group (Section 8.2.1).
     *
     * @param caId           binary trust anchor ID of the CA
     * @param logNumber      log number
     * @param landmarkNumber landmark number that names the group's high end
     */
    public static byte[] landmarkGroupId(byte[] caId, long logNumber, long landmarkNumber)
    {
        if (logNumber < 1 || logNumber > 0xFFFFL)
        {
            throw new IllegalArgumentException("log_number out of range: " + logNumber);
        }
        if (landmarkNumber < 0)
        {
            throw new IllegalArgumentException("landmark_number must be non-negative: " + landmarkNumber);
        }
        return concat(caId,
            encodeComponent(LANDMARK_GROUPS_ARC),
            encodeComponent(logNumber),
            encodeComponent(landmarkNumber));
    }

    /**
     * Converts a binary trust anchor ID into the dotted-decimal form used in
     * ASCII representations (e.g. for the issuer field UTF8String value and
     * inside CosignedMessage {@code cosigner_name} / {@code log_origin}).
     */
    public static String toDottedDecimal(byte[] binaryId)
    {
        return ASN1RelativeOID.fromContents(binaryId).getId();
    }

    /**
     * Converts a dotted-decimal trust anchor ID (e.g. {@code "32473.1.0.1"})
     * into its binary form.
     */
    public static byte[] fromDottedDecimal(String dotted)
    {
        return Utils.dottedDecimalToBinaryTrustAnchorID(dotted);
    }

    /**
     * Encodes a non-negative integer as a single OID component using base-128
     * with continuation bits, as defined for RELATIVE-OID contents in
     * Section 8.20 of X.690.
     */
    public static byte[] encodeComponent(long value)
    {
        return Utils.encodeBase128OidComponent(value);
    }

    private static byte[] concat(byte[]... parts)
    {
        int total = 0;
        for (byte[] p : parts)
        {
            total += p.length;
        }
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] p : parts)
        {
            System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }
}
