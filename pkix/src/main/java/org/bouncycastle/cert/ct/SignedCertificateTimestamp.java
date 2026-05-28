package org.bouncycastle.cert.ct;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.util.Arrays;

/**
 * A single Signed Certificate Timestamp (SCT) in the RFC 6962 (CT v1) wire
 * format. Decoded from the TLS-encoded payload of a
 * {@link SignedCertificateTimestampList}.
 *
 * <pre>
 *     enum { v1(0), (255) } Version;
 *
 *     struct {
 *         opaque key_id[32];
 *     } LogID;
 *
 *     opaque CtExtensions&lt;0..2^16-1&gt;;
 *
 *     struct {
 *         Version          sct_version;
 *         LogID            id;
 *         uint64           timestamp;
 *         CtExtensions     extensions;
 *         digitally-signed struct {
 *             Version       sct_version;
 *             SignatureType signature_type = certificate_timestamp;
 *             uint64        timestamp;
 *             LogEntryType  entry_type;
 *             select(entry_type) {
 *                 case x509_entry:    ASN.1Cert;
 *                 case precert_entry: PreCert;
 *             } signed_entry;
 *             CtExtensions  extensions;
 *         };
 *     } SignedCertificateTimestamp;
 * </pre>
 *
 * The {@code digitally-signed} value is the TLS 1.2 sec. 4.7 form: a one-byte
 * HashAlgorithm and a one-byte SignatureAlgorithm followed by a
 * two-byte-length-prefixed opaque signature. This class exposes the
 * algorithm pair and the raw signature bytes; computing the signed leaf
 * structure and verifying it against a log's public key is a higher-level
 * concern handled outside this decode-only API.
 *
 * <p>For RFC 9162 (CT v2), see {@link SignedCertificateTimestampDataV2}.</p>
 */
public class SignedCertificateTimestamp
{
    public static final int LOG_ID_LENGTH = 32;
    public static final int VERSION_V1 = 0;

    private final int sctVersion;
    private final byte[] logID;
    private final long timestamp;
    private final byte[] extensions;
    private final int hashAlgorithm;
    private final int signatureAlgorithm;
    private final byte[] signature;

    public SignedCertificateTimestamp(
        int sctVersion,
        byte[] logID,
        long timestamp,
        byte[] extensions,
        int hashAlgorithm,
        int signatureAlgorithm,
        byte[] signature)
    {
        if (logID == null || logID.length != LOG_ID_LENGTH)
        {
            throw new IllegalArgumentException("logID must be " + LOG_ID_LENGTH + " bytes");
        }
        if (extensions == null)
        {
            throw new NullPointerException("'extensions' cannot be null (use an empty array for no extensions)");
        }
        if (signature == null)
        {
            throw new NullPointerException("'signature' cannot be null");
        }
        if ((sctVersion & ~0xFF) != 0)
        {
            throw new IllegalArgumentException("sctVersion must fit in a uint8");
        }
        if ((hashAlgorithm & ~0xFF) != 0 || (signatureAlgorithm & ~0xFF) != 0)
        {
            throw new IllegalArgumentException("algorithm bytes must fit in a uint8");
        }

        this.sctVersion = sctVersion;
        this.logID = Arrays.clone(logID);
        this.timestamp = timestamp;
        this.extensions = Arrays.clone(extensions);
        this.hashAlgorithm = hashAlgorithm;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signature = Arrays.clone(signature);
    }

    /**
     * Decode an SCT from its serialized TLS form (the bytes that appear as
     * one {@code SerializedSCT} entry inside a
     * {@link SignedCertificateTimestampList}).
     */
    public static SignedCertificateTimestamp getInstance(byte[] encoded)
    {
        CTByteReader r = new CTByteReader(encoded);
        SignedCertificateTimestamp sct = decode(r);
        if (r.remaining() != 0)
        {
            throw new IllegalArgumentException("trailing bytes after SignedCertificateTimestamp");
        }
        return sct;
    }

    static SignedCertificateTimestamp decode(CTByteReader r)
    {
        int sctVersion = r.readU8();
        byte[] logID = r.readBytes(LOG_ID_LENGTH);
        long timestamp = r.readU64();
        byte[] extensions = r.readOpaqueU16();
        int hashAlgorithm = r.readU8();
        int signatureAlgorithm = r.readU8();
        byte[] signature = r.readOpaqueU16();

        return new SignedCertificateTimestamp(
            sctVersion, logID, timestamp, extensions,
            hashAlgorithm, signatureAlgorithm, signature);
    }

    /** SCT version byte. RFC 6962 defines only v1 (0). */
    public int getSctVersion()
    {
        return sctVersion;
    }

    /** 32-byte log identifier (SHA-256 of the log's DER-encoded public key). */
    public byte[] getLogID()
    {
        return Arrays.clone(logID);
    }

    /**
     * Issuance timestamp in milliseconds since the Unix epoch (Java
     * convention; the same value the wire form uses).
     */
    public long getTimestamp()
    {
        return timestamp;
    }

    /**
     * The {@code extensions} opaque blob carried in the SCT. RFC 6962 leaves
     * the contents unspecified; logs in the wild emit it empty.
     */
    public byte[] getExtensions()
    {
        return Arrays.clone(extensions);
    }

    /** TLS HashAlgorithm byte (sha256 = 4, etc.). */
    public int getHashAlgorithm()
    {
        return hashAlgorithm;
    }

    /** TLS SignatureAlgorithm byte (rsa = 1, dsa = 2, ecdsa = 3). */
    public int getSignatureAlgorithm()
    {
        return signatureAlgorithm;
    }

    /** Raw signature bytes (the opaque signature field from the digitally-signed struct). */
    public byte[] getSignature()
    {
        return Arrays.clone(signature);
    }

    /**
     * Serialize this SCT to its TLS wire form (the bytes that would be
     * carried as one {@code SerializedSCT} entry in a list).
     */
    public byte[] getEncoded()
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try
        {
            encode(out);
        }
        catch (IOException e)
        {
            // ByteArrayOutputStream doesn't throw.
            throw new IllegalStateException(e.getMessage(), e);
        }
        return out.toByteArray();
    }

    void encode(ByteArrayOutputStream out)
        throws IOException
    {
        CTByteWriter w = new CTByteWriter(out);
        w.writeU8(sctVersion);
        w.writeBytes(logID);
        w.writeU64(timestamp);
        w.writeOpaqueU16(extensions);
        w.writeU8(hashAlgorithm);
        w.writeU8(signatureAlgorithm);
        w.writeOpaqueU16(signature);
    }
}
