package org.bouncycastle.cert.ct;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.util.Arrays;

/**
 * The SCT body carried inside an RFC 9162 (CT v2) {@link TransItem} whose
 * versioned_type is {@code x509_sct_v2} (0x0102) or {@code precert_sct_v2}
 * (0x0103).
 *
 * <pre>
 *     struct {
 *         LogID    log_id;                       // opaque LogID&lt;2..127&gt;
 *         uint64   timestamp;
 *         Extension sct_extensions&lt;0..2^16-1&gt;;
 *         opaque   signature&lt;1..2^16-1&gt;;
 *     } SignedCertificateTimestampDataV2;
 * </pre>
 *
 * Notable differences vs the RFC 6962 v1 {@link SignedCertificateTimestamp}:
 * the log identifier is variable-length (a 1-byte length prefix preceding
 * 2-127 bytes, not a fixed 32-byte SHA-256); {@code sct_extensions} is a
 * structured list of {@link SctExtension} entries rather than an opaque
 * blob; the signature is plain opaque bytes (no embedded hash / signature
 * algorithm pair — the verifier discovers the algorithm from the log's
 * published key).
 */
public class SignedCertificateTimestampDataV2
{
    private final byte[] logID;
    private final long timestamp;
    private final List/*<SctExtension>*/ sctExtensions;
    private final byte[] signature;

    public SignedCertificateTimestampDataV2(
        byte[] logID,
        long timestamp,
        SctExtension[] sctExtensions,
        byte[] signature)
    {
        if (logID == null || logID.length < 2 || logID.length > 127)
        {
            throw new IllegalArgumentException("logID must be 2..127 bytes");
        }
        if (signature == null || signature.length < 1)
        {
            throw new IllegalArgumentException("signature must be non-empty");
        }
        if (sctExtensions == null)
        {
            throw new NullPointerException("'sctExtensions' cannot be null (use an empty array for none)");
        }

        this.logID = Arrays.clone(logID);
        this.timestamp = timestamp;
        List collected = new ArrayList(sctExtensions.length);
        for (int i = 0; i != sctExtensions.length; i++)
        {
            if (sctExtensions[i] == null)
            {
                throw new NullPointerException("sctExtensions[" + i + "] is null");
            }
            collected.add(sctExtensions[i]);
        }
        this.sctExtensions = Collections.unmodifiableList(collected);
        this.signature = Arrays.clone(signature);
    }

    /**
     * Decode the v2 SCT body from its serialized TLS form (the bytes of the
     * containing {@code TransItem.data} field, after the 2-byte
     * versioned_type prefix has been stripped).
     */
    public static SignedCertificateTimestampDataV2 getInstance(byte[] encoded)
    {
        CTByteReader r = new CTByteReader(encoded);
        SignedCertificateTimestampDataV2 sct = decode(r);
        if (r.remaining() != 0)
        {
            throw new IllegalArgumentException("trailing bytes after SignedCertificateTimestampDataV2");
        }
        return sct;
    }

    static SignedCertificateTimestampDataV2 decode(CTByteReader r)
    {
        byte[] logID = r.readOpaqueU8();
        if (logID.length < 2)
        {
            throw new IllegalArgumentException("logID must be 2..127 bytes (got " + logID.length + ")");
        }

        long timestamp = r.readU64();

        int extListLen = r.readU16();
        CTByteReader extReader = r.subReader(extListLen);
        List/*<SctExtension>*/ extensions = new ArrayList();
        while (extReader.remaining() > 0)
        {
            int extType = extReader.readU16();
            byte[] extData = extReader.readOpaqueU16();
            extensions.add(new SctExtension(extType, extData));
        }

        byte[] signature = r.readOpaqueU16();

        return new SignedCertificateTimestampDataV2(
            logID, timestamp,
            (SctExtension[])extensions.toArray(new SctExtension[extensions.size()]),
            signature);
    }

    /** Variable-length log identifier (2..127 bytes). */
    public byte[] getLogID()
    {
        return Arrays.clone(logID);
    }

    /** Issuance timestamp in milliseconds since the Unix epoch. */
    public long getTimestamp()
    {
        return timestamp;
    }

    /** Decoded {@code sct_extensions} entries; never {@code null}. */
    public List getSctExtensions()
    {
        return sctExtensions;
    }

    /** Raw signature bytes. */
    public byte[] getSignature()
    {
        return Arrays.clone(signature);
    }

    /**
     * Serialize this v2 SCT body to its TLS wire form (the bytes that
     * would form the {@code data} field of the containing TransItem).
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
            throw new IllegalStateException(e.getMessage(), e);
        }
        return out.toByteArray();
    }

    void encode(ByteArrayOutputStream out)
        throws IOException
    {
        CTByteWriter w = new CTByteWriter(out);
        w.writeOpaqueU8(logID);
        w.writeU64(timestamp);

        ByteArrayOutputStream extBody = new ByteArrayOutputStream();
        CTByteWriter ew = new CTByteWriter(extBody);
        for (int i = 0; i != sctExtensions.size(); i++)
        {
            SctExtension ext = (SctExtension)sctExtensions.get(i);
            ew.writeU16(ext.getExtensionType());
            ew.writeOpaqueU16(ext.getExtensionData());
        }
        w.writeOpaqueU16(extBody.toByteArray());

        w.writeOpaqueU16(signature);
    }
}
