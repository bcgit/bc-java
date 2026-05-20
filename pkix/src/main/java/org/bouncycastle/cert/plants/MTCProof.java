package org.bouncycastle.cert.plants;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.plants.MTCSignature;

/**
 * The MTCProof structure encoded in the X.509 certificate signatureValue per
 * <a href="https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/#section-6.1">draft-ietf-plants-merkle-tree-certs, Section 6.1</a>.
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
 *     uint64 start;
 *     uint64 end;
 *     HashValue inclusion_proof&lt;0..2^16-1&gt;;
 *     MTCSignature signatures&lt;0..2^16-1&gt;;
 * } MTCProof;
 * </pre>
 *
 * <p>The structure uses the TLS presentation language (Section 3 of RFC 8446)
 * and is encoded directly into the signatureValue BIT STRING with no ASN.1
 * wrapping.</p>
 */
public class MTCProof
{
    private final long start;
    private final long end;
    private final byte[] inclusionProof;
    private final List<MTCSignature> signatures;

    public MTCProof(long start, long end, byte[] inclusionProof, List<MTCSignature> signatures)
    {
        this.start = start;
        this.end = end;
        this.inclusionProof = inclusionProof.clone();
        this.signatures = Collections.unmodifiableList(new ArrayList<MTCSignature>(signatures));
    }

    /**
     * Parses an MTCProof from its TLS wire encoding.
     *
     * @param data the encoded bytes (the full BIT STRING value from the
     *             certificate's signatureValue)
     * @throws IOException if parsing fails
     */
    public MTCProof(byte[] data)
        throws IOException
    {
        ByteArrayInputStream in = new ByteArrayInputStream(data);

        this.start = Utils.readUint64(in);
        this.end = Utils.readUint64(in);

        int inclLen = Utils.readUint16(in);
        this.inclusionProof = new byte[inclLen];
        if (readFully(in, inclusionProof) != inclLen)
        {
            throw new IOException("Truncated inclusion_proof");
        }

        int sigsLen = Utils.readUint16(in);
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

            sigList.add(new MTCSignature(cosignerId, signature));
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

        Utils.writeUint64(baos, start);
        Utils.writeUint64(baos, end);

        if (inclusionProof.length > 0xFFFF)
        {
            throw new IOException("inclusion_proof too long: " + inclusionProof.length);
        }
        Utils.writeUint16(baos, inclusionProof.length);
        baos.write(inclusionProof);

        ByteArrayOutputStream sigsBaos = new ByteArrayOutputStream();
        for (MTCSignature sig : signatures)
        {
            byte[] cosignerId = sig.getCosignerId();
            byte[] signature = sig.getSignature();

            // Constructor checks already enforce the length ranges, but be defensive.
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
            Utils.writeUint16(sigsBaos, signature.length);
            sigsBaos.write(signature);
        }
        byte[] sigsBytes = sigsBaos.toByteArray();
        if (sigsBytes.length > 0xFFFF)
        {
            throw new IOException("signatures total length too long: " + sigsBytes.length);
        }

        Utils.writeUint16(baos, sigsBytes.length);
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
     *
     * @param hashSize the size of each hash in bytes
     * @return ordered list of hashes
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
