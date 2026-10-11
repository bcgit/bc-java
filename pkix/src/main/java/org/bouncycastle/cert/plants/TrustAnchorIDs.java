package org.bouncycastle.cert.plants;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1RelativeOID;
import org.bouncycastle.asn1.plants.MTCObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.Exceptions;

/**
 * Utilities for constructing and parsing the binary trust anchor IDs reserved
 * by Section 5.1 of draft-ietf-plants-merkle-tree-certs under each CA ID:
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

    /**
     * Maximum length, in bytes, of a trust anchor ID's binary representation.
     * Section 4 of draft-ietf-tls-trust-anchor-ids-06 states that it "MUST NOT
     * exceed 32 bytes" and transmits it as {@code opaque TrustAnchorID<1..32>},
     * so a valid trust anchor ID is 1..32 bytes. This bounds the IDs this class
     * builds and parses; the {@link MTCProof} wire structures still carry the
     * one-byte length prefix of draft-ietf-plants-merkle-tree-certs and read up
     * to 255 bytes.
     */
    public static final int MAX_ID_LENGTH = 32;

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
        requireValidId(caId, "caId");
        if (logNumber < 1 || logNumber > 0xFFFFL)
        {
            throw new IllegalArgumentException("log_number out of range [1, 65535]: " + logNumber);
        }
        return requireValidId(
            concat(caId, encodeComponent(LOGS_ARC), encodeComponent(logNumber)), "log ID");
    }

    /**
     * Composes the 64-bit certificate serial number per Section 6.2 of
     * draft-ietf-plants-merkle-tree-certs:
     * <pre>
     *     serial = (log_number &lt;&lt; 48) | index
     * </pre>
     * The validator decodes the same encoding in
     * {@link MerkleTreeCertificateValidator#validateCertificate}; this method
     * is the issuer-side counterpart.
     *
     * @param logNumber log number ({@code 1 <= logNumber <= 2^16-1}, Section 5.2)
     * @param index     entry index in the log ({@code 0 <= index <= 2^48-1})
     */
    public static BigInteger certSerial(long logNumber, long index)
    {
        if (logNumber < 1 || logNumber > 0xFFFFL)
        {
            throw new IllegalArgumentException("log_number out of range [1, 65535]: " + logNumber);
        }
        if (index < 0 || index > 0xFFFFFFFFFFFFL)
        {
            throw new IllegalArgumentException("index out of uint48 range: " + index);
        }
        // (logNumber << 48) overflows a signed long for log_number >= 32768; the
        // draft requires serials to be positive and at most 2^64-1 (Section 6.2).
        return BigInteger.valueOf(logNumber).shiftLeft(48).or(BigInteger.valueOf(index));
    }

    /**
     * Equivalent to {@link #certSerial(long, long)} with the log number taken
     * from {@code log.getLogNumber()}.
     */
    public static BigInteger certSerial(MTCLog log, long index)
    {
        return certSerial(log.getLogNumber(), index);
    }

    /**
     * Builds the binary trust anchor ID of a landmark, {@code {caID landmarks(1) N L}}
     * (Sections 5.1 and 8.2). Section 5.1 allocates these OIDs for positive
     * landmark numbers only: landmark 0 always has tree size zero and the empty
     * subtrees, so it never needs an ID.
     *
     * @param caId           binary trust anchor ID of the CA
     * @param logNumber      log number
     * @param landmarkNumber landmark number ({@code landmarkNumber >= 1})
     */
    public static byte[] landmarkId(byte[] caId, long logNumber, long landmarkNumber)
    {
        requireValidId(caId, "caId");
        if (logNumber < 1 || logNumber > 0xFFFFL)
        {
            throw new IllegalArgumentException("log_number out of range: " + logNumber);
        }
        if (landmarkNumber < 1)
        {
            throw new IllegalArgumentException("landmark_number must be positive: " + landmarkNumber);
        }
        return requireValidId(concat(caId,
            encodeComponent(LANDMARKS_ARC),
            encodeComponent(logNumber),
            encodeComponent(landmarkNumber)), "landmark ID");
    }

    /**
     * Builds the binary trust anchor ID of a landmark group,
     * {@code {caID landmarkGroups(2) N L}} (Section 8.2.1): the group of the CA
     * ID itself, selecting standalone certificates, and the landmarks 0 to
     * {@code L} of log {@code N}. As with {@link #landmarkId}, Section 5.1
     * allocates these OIDs for positive landmark numbers only.
     *
     * @param caId           binary trust anchor ID of the CA
     * @param logNumber      log number
     * @param landmarkNumber landmark number that names the group's high end
     *                       ({@code landmarkNumber >= 1})
     */
    public static byte[] landmarkGroupId(byte[] caId, long logNumber, long landmarkNumber)
    {
        requireValidId(caId, "caId");
        if (logNumber < 1 || logNumber > 0xFFFFL)
        {
            throw new IllegalArgumentException("log_number out of range: " + logNumber);
        }
        if (landmarkNumber < 1)
        {
            throw new IllegalArgumentException("landmark_number must be positive: " + landmarkNumber);
        }
        return requireValidId(concat(caId,
            encodeComponent(LANDMARK_GROUPS_ARC),
            encodeComponent(logNumber),
            encodeComponent(landmarkNumber)), "landmark group ID");
    }

    /**
     * Builds the issuer {@link X500Name} for a Merkle Tree certificate: a
     * single RDN whose {@code id-rdna-trustAnchorID} attribute carries the
     * CA's trust anchor ID as a RELATIVE-OID (Section 5.1 of
     * draft-ietf-plants-merkle-tree-certs). The validator concatenates this
     * with the cert serial's {@code log_number} to recover the issuance log's
     * full trust anchor ID.
     *
     * <p>Earlier drafts used a UTF8String of the dotted-decimal ID for
     * experimentation; {@link MerkleTreeCertificateValidator#extractCaIdFromIssuer(X500Name)}
     * still reads that form but it is no longer written.</p>
     *
     * @param caTrustAnchorIdDotted dotted-decimal form of the CA's trust
     *                              anchor ID (e.g. {@code "32473.1"})
     */
    public static X500Name issuerName(String caTrustAnchorIdDotted)
    {
        AttributeTypeAndValue attr = new AttributeTypeAndValue(
            MTCObjectIdentifiers.id_rdna_trustAnchorID,
            new ASN1RelativeOID(caTrustAnchorIdDotted));
        return new X500Name(new RDN[]{new RDN(attr)});
    }

    /**
     * Converts a binary trust anchor ID into the dotted-decimal form used in
     * ASCII representations (e.g. inside the CosignedSubtree
     * {@code cosigner_name} / {@code log_origin}).
     */
    public static String toDottedDecimal(byte[] binaryId)
    {
        return ASN1RelativeOID.fromContents(binaryId).getId();
    }

    /**
     * Converts a dotted-decimal trust anchor ID (e.g. {@code "32473.1.0.1"})
     * into its binary form: the base-128 encoded OID-component bytes with no
     * ASN.1 tag or length prefix (Section 3 of draft-ietf-tls-trust-anchor-ids).
     */
    public static byte[] fromDottedDecimal(String dotted)
    {
        // Reuse ASN1RelativeOID for the per-component base-128 encoding, then
        // strip its DER tag and length header so only the contents octets remain.
        ASN1RelativeOID relOid = new ASN1RelativeOID(dotted);
        byte[] encoded;
        try
        {
            encoded = relOid.getEncoded();
        }
        catch (IOException e)
        {
            // Encoding a RELATIVE-OID we just constructed in memory should not fail.
            throw Exceptions.illegalStateException("unable to encode RELATIVE-OID for " + dotted, e);
        }
        return requireValidId(stripDerHeader(encoded), "trust anchor ID");
    }

    /**
     * Encodes a non-negative integer as a single OID component using base-128
     * with continuation bits, as defined for RELATIVE-OID contents in
     * Section 8.20 of X.690.
     */
    public static byte[] encodeComponent(long value)
    {
        if (value < 0)
        {
            throw new IllegalArgumentException("OID component cannot be negative");
        }
        if (value == 0)
        {
            return new byte[]{0};
        }
        int n = 0;
        long t = value;
        while (t > 0)
        {
            n++;
            t >>>= 7;
        }
        byte[] out = new byte[n];
        for (int i = n - 1; i >= 0; i--)
        {
            int b = (int)((value >>> (7 * i)) & 0x7F);
            if (i > 0)
            {
                b |= 0x80;
            }
            out[n - 1 - i] = (byte)b;
        }
        return out;
    }

    /**
     * Enforces the {@code opaque TrustAnchorID<1..2^8-1>} length bound of
     * Section 3 / Section 4.1 of draft-ietf-tls-trust-anchor-ids: a trust anchor
     * ID's binary representation must be 1..{@link #MAX_ID_LENGTH} bytes.
     *
     * @return {@code id}, when valid, to allow chaining at a return site
     */
    private static byte[] requireValidId(byte[] id, String what)
    {
        if (id == null)
        {
            throw new NullPointerException(what + " cannot be null");
        }
        if (id.length < 1 || id.length > MAX_ID_LENGTH)
        {
            throw new IllegalArgumentException(what + " binary length must be 1.." + MAX_ID_LENGTH
                + " bytes (draft-ietf-tls-trust-anchor-ids sec. 4), got " + id.length);
        }
        return id;
    }

    private static byte[] stripDerHeader(byte[] der)
    {
        if (der.length < 2)
        {
            throw new IllegalArgumentException("DER encoding too short");
        }
        int lengthByte = der[1] & 0xFF;
        int contentLength;
        int headerLength;
        if ((lengthByte & 0x80) == 0)
        {
            contentLength = lengthByte;
            headerLength = 2;
        }
        else
        {
            int numLengthBytes = lengthByte & 0x7F;
            if (numLengthBytes == 0 || der.length < 2 + numLengthBytes)
            {
                throw new IllegalArgumentException("Invalid DER length encoding");
            }
            contentLength = 0;
            for (int i = 0; i < numLengthBytes; i++)
            {
                contentLength = (contentLength << 8) | (der[2 + i] & 0xFF);
            }
            headerLength = 2 + numLengthBytes;
        }
        if (headerLength + contentLength != der.length)
        {
            throw new IllegalArgumentException("DER content length does not match");
        }
        byte[] out = new byte[contentLength];
        System.arraycopy(der, headerLength, out, 0, contentLength);
        return out;
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
