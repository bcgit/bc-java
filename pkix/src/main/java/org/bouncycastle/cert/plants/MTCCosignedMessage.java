package org.bouncycastle.cert.plants;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1RelativeOID;
import org.bouncycastle.util.Strings;

/**
 * Wire encoder for the CosignedMessage struct defined by Section 5.3.1 of
 * <a href="https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/">draft-ietf-plants-merkle-tree-certs</a>:
 *
 * <pre>
 * struct {
 *     uint8 label[12] = "subtree/v1\n\0";
 *     opaque cosigner_name&lt;1..2^8-1&gt;;
 *     uint64 timestamp;
 *     opaque log_origin&lt;1..2^8-1&gt;;
 *     uint64 start;
 *     uint64 end;
 *     HashValue subtree_hash;
 * } CosignedMessage;
 * </pre>
 *
 * <p>{@code cosigner_name} and {@code log_origin} are the ASCII strings
 * {@code "oid/1.3.6.1.4.1." + <dotted-decimal trust anchor ID>}, constructed
 * from the binary trust anchor IDs supplied by the caller.</p>
 *
 * @see MTCSignatureVerifier
 * @see MTCCosignerVerifier
 */
public final class MTCCosignedMessage
{
    private static final byte[] SUBTREE_LABEL = new byte[]{
        's', 'u', 'b', 't', 'r', 'e', 'e', '/', 'v', '1', (byte)0x0A, (byte)0x00
    };

    private static final byte[] OID_PREFIX = Strings.toByteArray("oid/1.3.6.1.4.1.");

    private MTCCosignedMessage()
    {
    }

    /**
     * Equivalent to {@link #encode(byte[], long, long, long, byte[], byte[])} with
     * {@code timestamp == 0}, which is the only value permitted inside an MTCProof
     * cosigner signature per Section 6.1 of the draft.
     */
    public static byte[] encode(
        byte[] logId,
        long start,
        long end,
        byte[] subtreeHash,
        byte[] cosignerId)
        throws IOException
    {
        return encode(logId, 0L, start, end, subtreeHash, cosignerId);
    }

    /**
     * Equivalent to {@link #encode(byte[], long, long, byte[], byte[])} taking
     * the log ID and subtree window from an {@link MTCLog}. Convenient for
     * issuer-side code that already carries an MTCLog object.
     */
    public static byte[] encode(
        MTCLog log,
        byte[] subtreeHash,
        byte[] cosignerId)
        throws IOException
    {
        return encode(log.getLogId(), 0L, log.getStart(), log.getEnd(), subtreeHash, cosignerId);
    }

    /**
     * Equivalent to {@link #encode(byte[], long, long, long, byte[], byte[])}
     * taking the log ID and subtree window from an {@link MTCLog}. Use the
     * non-MTCProof case where a non-zero timestamp is required.
     */
    public static byte[] encode(
        MTCLog log,
        long timestamp,
        byte[] subtreeHash,
        byte[] cosignerId)
        throws IOException
    {
        return encode(log.getLogId(), timestamp, log.getStart(), log.getEnd(), subtreeHash, cosignerId);
    }

    /**
     * Encodes a CosignedMessage in the wire format defined by Section 5.3.1.
     *
     * @param logId       binary trust anchor ID of the log
     * @param timestamp   POSIX timestamp (zero inside an MTCProof; non-zero elsewhere)
     * @param start       subtree start index
     * @param end         subtree end index
     * @param subtreeHash hash of the subtree
     * @param cosignerId  binary trust anchor ID of the cosigner
     * @return the encoded CosignedMessage bytes
     */
    public static byte[] encode(
        byte[] logId,
        long timestamp,
        long start,
        long end,
        byte[] subtreeHash,
        byte[] cosignerId)
        throws IOException
    {
        byte[] cosignerName = asciiName(cosignerId);
        byte[] logOrigin = asciiName(logId);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(SUBTREE_LABEL);
        writeOpaque1(baos, cosignerName);
        writeUint64(baos, timestamp);
        writeOpaque1(baos, logOrigin);
        writeUint64(baos, start);
        writeUint64(baos, end);
        baos.write(subtreeHash);
        return baos.toByteArray();
    }

    private static byte[] asciiName(byte[] binaryTrustAnchorID)
    {
        String dotted = ASN1RelativeOID.fromContents(binaryTrustAnchorID).getId();
        byte[] dottedBytes = Strings.toByteArray(dotted);
        byte[] out = new byte[OID_PREFIX.length + dottedBytes.length];
        System.arraycopy(OID_PREFIX, 0, out, 0, OID_PREFIX.length);
        System.arraycopy(dottedBytes, 0, out, OID_PREFIX.length, dottedBytes.length);
        return out;
    }

    private static void writeOpaque1(ByteArrayOutputStream baos, byte[] data)
    {
        if (data.length < 1 || data.length > 255)
        {
            throw new IllegalArgumentException("opaque<1..255> length must be 1..255 bytes, got " + data.length);
        }
        baos.write(data.length);
        baos.write(data, 0, data.length);
    }

    private static void writeUint64(ByteArrayOutputStream baos, long value)
    {
        baos.write((byte)(value >>> 56));
        baos.write((byte)(value >>> 48));
        baos.write((byte)(value >>> 40));
        baos.write((byte)(value >>> 32));
        baos.write((byte)(value >>> 24));
        baos.write((byte)(value >>> 16));
        baos.write((byte)(value >>> 8));
        baos.write((byte)value);
    }
}
