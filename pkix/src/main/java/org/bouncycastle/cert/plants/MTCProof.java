package org.bouncycastle.cert.plants;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The MTCProof structure encoded in the X.509 certificate signatureValue per
 * <a href="https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/">draft-ietf-plants-merkle-tree-certs-04</a>,
 * Section 6.1.
 *
 * <pre>
 * opaque HashValue[HASH_SIZE];
 *
 * struct {
 *     TrustAnchorID cosigner_id;
 *     opaque signature&lt;0..2^16-1&gt;;
 * } MTCSignature;
 *
 * struct {
 *     uint48 start;
 *     uint48 end;
 *     HashValue inclusion_proof&lt;0..2^16-1&gt;;
 *     MTCSignature signatures&lt;0..2^16-1&gt;;
 * } MTCProof;
 * </pre>
 *
 * <p>{@code start} and {@code end} are 6-byte unsigned big-endian integers
 * (draft-04 shrank these from {@code uint64}). Entries of {@code signatures}
 * MUST have unique {@code cosigner_id}s and MUST be ordered first by length
 * (shorter byte strings before longer) and then lexicographically.</p>
 */
public class MTCProof
{
    /** Maximum value of a uint48 (2^48 - 1). */
    public static final long UINT48_MAX = 0xFFFFFFFFFFFFL;

    private final long start;
    private final long end;
    private final byte[] inclusionProof;
    private final List<MTCSignature> signatures;

    /**
     * Constructs an MTCProof, validating uint48 range and canonical ordering of
     * the signatures list.
     *
     * @throws IllegalArgumentException if start or end exceeds 2^48-1, or if
     *                                  the supplied signatures contain a
     *                                  duplicate cosigner_id or are not in
     *                                  canonical order
     */
    public MTCProof(long start, long end, byte[] inclusionProof, List<MTCSignature> signatures)
    {
        if (start < 0 || start > UINT48_MAX)
        {
            throw new IllegalArgumentException("start out of uint48 range: " + start);
        }
        if (end < 0 || end > UINT48_MAX)
        {
            throw new IllegalArgumentException("end out of uint48 range: " + end);
        }
        checkSignatureOrder(signatures);
        this.start = start;
        this.end = end;
        this.inclusionProof = inclusionProof.clone();
        this.signatures = Collections.unmodifiableList(new ArrayList<MTCSignature>(signatures));
    }

    /**
     * Parses an MTCProof from its TLS wire encoding (the contents of the
     * certificate's {@code signatureValue} BIT STRING, byte-aligned, with no
     * unused-bits prefix).
     *
     * @throws IOException if parsing fails or if the signatures list violates
     *                     the canonical-ordering rules in Section 6.1
     */
    public MTCProof(byte[] data)
        throws IOException
    {
        ByteArrayInputStream in = new ByteArrayInputStream(data);

        this.start = MTCEncoding.readUint48(in);
        this.end = MTCEncoding.readUint48(in);

        int inclLen = MTCEncoding.readUint16(in);
        this.inclusionProof = new byte[inclLen];
        if (readFully(in, inclusionProof) != inclLen)
        {
            throw new IOException("Truncated inclusion_proof");
        }

        int sigsLen = MTCEncoding.readUint16(in);
        byte[] sigsData = new byte[sigsLen];
        if (readFully(in, sigsData) != sigsLen)
        {
            throw new IOException("Truncated signatures data");
        }
        if (in.available() != 0)
        {
            throw new IOException("Trailing bytes after MTCProof");
        }

        List<MTCSignature> sigList = new ArrayList<MTCSignature>();
        ByteArrayInputStream sigsIn = new ByteArrayInputStream(sigsData);
        byte[] prevCosignerId = null;
        while (sigsIn.available() > 0)
        {
            int idLen = sigsIn.read();
            if (idLen < 1)
            {
                throw new IOException("Invalid cosigner_id length: " + idLen);
            }
            byte[] cosignerId = new byte[idLen];
            if (readFully(sigsIn, cosignerId) != idLen)
            {
                throw new IOException("Truncated cosigner_id");
            }

            if (sigsIn.available() < 2)
            {
                throw new IOException("Truncated signature length");
            }
            int sigLen = (sigsIn.read() << 8) | sigsIn.read();
            byte[] signature = new byte[sigLen];
            if (readFully(sigsIn, signature) != sigLen)
            {
                throw new IOException("Truncated signature");
            }

            if (prevCosignerId != null)
            {
                int cmp = compareCosignerIds(prevCosignerId, cosignerId);
                if (cmp == 0)
                {
                    throw new IOException("Duplicate cosigner_id in MTCProof.signatures");
                }
                if (cmp > 0)
                {
                    throw new IOException("MTCProof.signatures not in canonical order");
                }
            }
            sigList.add(new MTCSignature(cosignerId, signature));
            prevCosignerId = cosignerId;
        }
        this.signatures = Collections.unmodifiableList(sigList);
    }

    /**
     * @return the TLS wire encoding of this MTCProof
     * @throws IOException if a length constraint is violated
     */
    public byte[] encode()
        throws IOException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        MTCEncoding.writeUint48(baos, start);
        MTCEncoding.writeUint48(baos, end);

        if (inclusionProof.length > 0xFFFF)
        {
            throw new IOException("inclusion_proof too long: " + inclusionProof.length);
        }
        MTCEncoding.writeUint16(baos, inclusionProof.length);
        baos.write(inclusionProof);

        ByteArrayOutputStream sigsBaos = new ByteArrayOutputStream();
        for (MTCSignature sig : signatures)
        {
            byte[] cosignerId = sig.getCosignerId();
            byte[] signature = sig.getSignature();

            if (cosignerId.length < 1 || cosignerId.length > 255)
            {
                throw new IOException("Invalid cosigner_id length: " + cosignerId.length);
            }
            if (signature.length > 0xFFFF)
            {
                throw new IOException("Signature too long: " + signature.length);
            }

            sigsBaos.write(cosignerId.length);
            sigsBaos.write(cosignerId);
            MTCEncoding.writeUint16(sigsBaos, signature.length);
            sigsBaos.write(signature);
        }
        byte[] sigsBytes = sigsBaos.toByteArray();
        if (sigsBytes.length > 0xFFFF)
        {
            throw new IOException("signatures total length too long: " + sigsBytes.length);
        }

        MTCEncoding.writeUint16(baos, sigsBytes.length);
        baos.write(sigsBytes);

        return baos.toByteArray();
    }

    public long getStart()
    {
        return start;
    }

    public long getEnd()
    {
        return end;
    }

    public byte[] getInclusionProof()
    {
        return inclusionProof.clone();
    }

    public List<MTCSignature> getSignatures()
    {
        return signatures;
    }

    /**
     * Splits the concatenated {@link #getInclusionProof() inclusion proof} into
     * individual hash values of the given size.
     */
    public List<byte[]> getHashList(int hashSize)
    {
        if (inclusionProof.length % hashSize != 0)
        {
            throw new IllegalArgumentException("Inclusion proof length not a multiple of hash size");
        }
        List<byte[]> list = new ArrayList<byte[]>(inclusionProof.length / hashSize);
        for (int i = 0; i < inclusionProof.length; i += hashSize)
        {
            byte[] hash = new byte[hashSize];
            System.arraycopy(inclusionProof, i, hash, 0, hashSize);
            list.add(hash);
        }
        return list;
    }

    /**
     * The canonical comparator on cosigner_id byte strings, per Section 6.1:
     * shorter byte strings come first, ties are broken lexicographically
     * (unsigned).
     */
    public static int compareCosignerIds(byte[] a, byte[] b)
    {
        if (a.length != b.length)
        {
            return Integer.compare(a.length, b.length);
        }
        for (int i = 0; i < a.length; i++)
        {
            int diff = (a[i] & 0xFF) - (b[i] & 0xFF);
            if (diff != 0)
            {
                return diff;
            }
        }
        return 0;
    }

    private static void checkSignatureOrder(List<MTCSignature> sigs)
    {
        byte[] prev = null;
        for (MTCSignature sig : sigs)
        {
            byte[] id = sig.getCosignerId();
            if (prev != null)
            {
                int cmp = compareCosignerIds(prev, id);
                if (cmp == 0)
                {
                    throw new IllegalArgumentException("Duplicate cosigner_id in MTCProof.signatures");
                }
                if (cmp > 0)
                {
                    throw new IllegalArgumentException("MTCProof.signatures not in canonical order");
                }
            }
            prev = id;
        }
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
