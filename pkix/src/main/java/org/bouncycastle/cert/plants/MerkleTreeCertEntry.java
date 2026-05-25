package org.bouncycastle.cert.plants;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.x509.TBSCertificateLogEntry;
import org.bouncycastle.util.Arrays;

/**
 * Parses (and encodes) a single log entry per Section 5.2.1 of
 * draft-ietf-plants-merkle-tree-certs:
 *
 * <pre>
 * struct {
 *     MerkleTreeCertEntryExtension extensions&lt;0..2^16-1&gt;;
 *     MerkleTreeCertEntryType type;
 *     select (type) {
 *        case null_entry: Empty;
 *        case tbs_cert_entry: opaque tbs_cert_entry_data[N];
 *     }
 * } MerkleTreeCertEntry;
 * </pre>
 *
 * <p>For {@code tbs_cert_entry}, the body is the DER <em>contents</em> octets
 * of a {@link TBSCertificateLogEntry} — that is, the SEQUENCE tag and length
 * octets are stripped. {@link #getTbsCertEntry()} reattaches a DER SEQUENCE
 * wrapper and decodes it for callers who want the structured form.</p>
 *
 * <p>{@code MerkleTreeCertEntry} is parsed in a length-framed context (the
 * caller knows how many bytes belong to it); the byte-array constructor
 * therefore consumes its full input.</p>
 */
public class MerkleTreeCertEntry
{
    private final List<MerkleTreeCertEntryExtension> extensions;
    private final int type;
    private final byte[] body;

    /**
     * Constructs an entry from its component parts.
     *
     * @param extensions  ordered (ascending {@code extension_type}, no duplicates)
     * @param type        a {@link MerkleTreeCertEntryType} value (uint16)
     * @param body        the type-specific body bytes (empty for {@code null_entry},
     *                    the {@code tbs_cert_entry_data} contents for {@code tbs_cert_entry})
     */
    public MerkleTreeCertEntry(
        List<MerkleTreeCertEntryExtension> extensions,
        int type,
        byte[] body)
    {
        if (type < 0 || type > 0xFFFF)
        {
            throw new IllegalArgumentException("MerkleTreeCertEntryType out of uint16 range: " + type);
        }
        checkExtensionOrder(extensions);
        if (type == MerkleTreeCertEntryType.NULL_ENTRY && body.length != 0)
        {
            throw new IllegalArgumentException("null_entry body must be empty");
        }
        this.extensions = Collections.unmodifiableList(
            new ArrayList<MerkleTreeCertEntryExtension>(extensions));
        this.type = type;
        this.body = body.clone();
    }

    /**
     * Parses a {@code MerkleTreeCertEntry} from its TLS wire encoding. The
     * input MUST contain exactly one entry; trailing bytes are rejected.
     */
    public MerkleTreeCertEntry(byte[] data)
        throws IOException
    {
        ByteArrayInputStream in = new ByteArrayInputStream(data);

        int extLen = MTCEncoding.readUint16(in);
        byte[] extData = new byte[extLen];
        if (readFully(in, extData) != extLen)
        {
            throw new IOException("Truncated extensions");
        }
        this.extensions = Collections.unmodifiableList(parseExtensions(extData));

        if (in.available() < 2)
        {
            throw new IOException("Truncated MerkleTreeCertEntryType");
        }
        this.type = MTCEncoding.readUint16(in);

        // Per the spec, the body consumes the rest of the input.
        byte[] rest = new byte[in.available()];
        readFully(in, rest);

        if (type == MerkleTreeCertEntryType.NULL_ENTRY && rest.length != 0)
        {
            throw new IOException("null_entry has non-empty body");
        }
        this.body = rest;
    }

    public List<MerkleTreeCertEntryExtension> getExtensions()
    {
        return extensions;
    }

    public int getType()
    {
        return type;
    }

    /**
     * @return the type-specific body bytes — empty for {@code null_entry},
     *         the {@code tbs_cert_entry_data} contents (DER body of a
     *         TBSCertificateLogEntry without its SEQUENCE wrapper) for
     *         {@code tbs_cert_entry}, or the raw bytes for any future type
     */
    public byte[] getBody()
    {
        return Arrays.clone(body);
    }

    /**
     * Reattaches a DER SEQUENCE wrapper to {@link #getBody()} and decodes the
     * result as a {@link TBSCertificateLogEntry}.
     *
     * @throws IllegalStateException if {@link #getType()} is not {@code tbs_cert_entry}
     * @throws IOException           if the wrapped bytes do not decode as a TBSCertificateLogEntry
     */
    public TBSCertificateLogEntry getTbsCertEntry()
        throws IOException
    {
        if (type != MerkleTreeCertEntryType.TBS_CERT_ENTRY)
        {
            throw new IllegalStateException(
                "MerkleTreeCertEntry is not a tbs_cert_entry (type=" + type + ")");
        }
        return TBSCertificateLogEntry.getInstance(wrapInDerSequence(body));
    }

    /**
     * @return the TLS wire encoding of this entry
     * @throws IOException if a length constraint is violated
     */
    public byte[] encode()
        throws IOException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ByteArrayOutputStream extBody = new ByteArrayOutputStream();
        for (MerkleTreeCertEntryExtension ext : extensions)
        {
            MTCEncoding.writeUint16(extBody, ext.getExtensionType());
            byte[] data = ext.getExtensionData();
            MTCEncoding.writeUint16(extBody, data.length);
            extBody.write(data);
        }
        byte[] extBytes = extBody.toByteArray();
        if (extBytes.length > 0xFFFF)
        {
            throw new IOException("extensions total length too long: " + extBytes.length);
        }
        MTCEncoding.writeUint16(baos, extBytes.length);
        baos.write(extBytes);

        MTCEncoding.writeUint16(baos, type);
        baos.write(body);

        return baos.toByteArray();
    }

    private static void checkExtensionOrder(List<MerkleTreeCertEntryExtension> exts)
    {
        int prev = -1;
        for (MerkleTreeCertEntryExtension ext : exts)
        {
            int t = ext.getExtensionType();
            if (t == prev)
            {
                throw new IllegalArgumentException(
                    "Duplicate extension_type in MerkleTreeCertEntry.extensions: " + t);
            }
            if (t < prev)
            {
                throw new IllegalArgumentException(
                    "MerkleTreeCertEntry.extensions not in ascending order by extension_type");
            }
            prev = t;
        }
    }

    private static List<MerkleTreeCertEntryExtension> parseExtensions(byte[] data)
        throws IOException
    {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        List<MerkleTreeCertEntryExtension> out = new ArrayList<MerkleTreeCertEntryExtension>();
        int prevType = -1;
        while (in.available() > 0)
        {
            if (in.available() < 4)
            {
                throw new IOException("Truncated MerkleTreeCertEntryExtension header");
            }
            int extType = MTCEncoding.readUint16(in);
            int extDataLen = MTCEncoding.readUint16(in);
            byte[] extData = new byte[extDataLen];
            if (readFully(in, extData) != extDataLen)
            {
                throw new IOException("Truncated extension_data");
            }
            if (extType == prevType)
            {
                throw new IOException(
                    "Duplicate extension_type in MerkleTreeCertEntry.extensions: " + extType);
            }
            if (extType < prevType)
            {
                throw new IOException(
                    "MerkleTreeCertEntry.extensions not in ascending order by extension_type");
            }
            out.add(new MerkleTreeCertEntryExtension(extType, extData));
            prevType = extType;
        }
        return out;
    }

    /**
     * Wraps {@code contents} as the body of a DER SEQUENCE (tag 0x30 followed
     * by the minimum-length encoding of {@code contents.length}).
     */
    private static byte[] wrapInDerSequence(byte[] contents)
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x30);
        int len = contents.length;
        if (len < 0x80)
        {
            out.write(len);
        }
        else if (len < 0x100)
        {
            out.write(0x81);
            out.write(len);
        }
        else if (len < 0x10000)
        {
            out.write(0x82);
            out.write((len >>> 8) & 0xFF);
            out.write(len & 0xFF);
        }
        else if (len < 0x1000000)
        {
            out.write(0x83);
            out.write((len >>> 16) & 0xFF);
            out.write((len >>> 8) & 0xFF);
            out.write(len & 0xFF);
        }
        else
        {
            out.write(0x84);
            out.write((len >>> 24) & 0xFF);
            out.write((len >>> 16) & 0xFF);
            out.write((len >>> 8) & 0xFF);
            out.write(len & 0xFF);
        }
        out.write(contents, 0, contents.length);
        return out.toByteArray();
    }

    private static int readFully(ByteArrayInputStream in, byte[] b)
    {
        int off = 0;
        int len = b.length;
        while (len > 0)
        {
            int count = in.read(b, off, len);
            if (count < 0)
            {
                return off;
            }
            off += count;
            len -= count;
        }
        return off;
    }
}
