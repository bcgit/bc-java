package org.bouncycastle.cert.ct;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

/**
 * One TLS-encoded item from an RFC 9162 (CT v2)
 * {@link TransItemList}. The structure is a 2-byte
 * {@code VersionedTransType} followed by the type-specific {@code data}
 * payload; this class retains the payload as opaque bytes and provides a
 * typed decoder for the only payload kind the certificate-side decoder
 * needs to interpret in practice:
 * {@link #getSignedCertificateTimestampDataV2()}. Other payload kinds
 * (log entries, signed tree heads, consistency / inclusion proofs) are
 * still recoverable through {@link #getRawData()}; layering structured
 * decoders on top is intentionally left to consumers that need them.
 *
 * <pre>
 *     enum {
 *         x509_entry_v2(0x0100), precert_entry_v2(0x0101),
 *         x509_sct_v2(0x0102),   precert_sct_v2(0x0103),
 *         signed_tree_head_v2(0x0104),
 *         consistency_proof_v2(0x0105),
 *         inclusion_proof_v2(0x0106),
 *         reserved_rfc6962(0x0000..0x00FF),
 *         reserved_experimentaluse(0xE000..0xEFFF),
 *         reserved_privateuse(0xF000..0xFFFF),
 *         (0xFFFF)
 *     } VersionedTransType;
 *
 *     struct {
 *         VersionedTransType versioned_type;
 *         select (versioned_type) {
 *             case x509_sct_v2:    SignedCertificateTimestampDataV2;
 *             case precert_sct_v2: SignedCertificateTimestampDataV2;
 *             ...
 *         } data;
 *     } TransItem;
 * </pre>
 */
public class TransItem
{
    public static final int x509_entry_v2        = 0x0100;
    public static final int precert_entry_v2     = 0x0101;
    public static final int x509_sct_v2          = 0x0102;
    public static final int precert_sct_v2       = 0x0103;
    public static final int signed_tree_head_v2  = 0x0104;
    public static final int consistency_proof_v2 = 0x0105;
    public static final int inclusion_proof_v2   = 0x0106;

    private final int versionedType;
    private final byte[] data;

    public TransItem(int versionedType, byte[] data)
    {
        if ((versionedType & ~0xFFFF) != 0)
        {
            throw new IllegalArgumentException("versionedType must fit in a uint16");
        }
        if (data == null)
        {
            throw new NullPointerException("'data' cannot be null");
        }

        this.versionedType = versionedType;
        this.data = Arrays.clone(data);
    }

    /**
     * Decode a TransItem from its serialized form (the bytes that appear
     * as one {@code SerializedTransItem} entry inside a
     * {@link TransItemList}).
     */
    public static TransItem getInstance(byte[] encoded)
    {
        CTByteReader r = new CTByteReader(encoded);
        int type = r.readU16();
        byte[] data = r.readBytes(r.remaining());
        return new TransItem(type, data);
    }

    public int getVersionedType()
    {
        return versionedType;
    }

    /**
     * The raw {@code data} payload bytes — i.e. the SerializedTransItem
     * minus the 2-byte versioned_type prefix. The caller is responsible
     * for parsing them according to {@link #getVersionedType()}.
     */
    public byte[] getRawData()
    {
        return Arrays.clone(data);
    }

    /**
     * When this item is a v2 SCT ({@code x509_sct_v2} or
     * {@code precert_sct_v2}), return the decoded payload; otherwise
     * return {@code null}.
     */
    public SignedCertificateTimestampDataV2 getSignedCertificateTimestampDataV2()
    {
        if (versionedType != x509_sct_v2 && versionedType != precert_sct_v2)
        {
            return null;
        }
        return SignedCertificateTimestampDataV2.getInstance(data);
    }

    /**
     * Serialize this TransItem to its TLS wire form.
     */
    public byte[] getEncoded()
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try
        {
            CTByteWriter w = new CTByteWriter(out);
            w.writeU16(versionedType);
            w.writeBytes(data);
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
        return out.toByteArray();
    }
}
