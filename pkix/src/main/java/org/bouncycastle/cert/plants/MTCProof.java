package org.bouncycastle.cert.plants;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.plants.MTCSignature;

/**
 * TLS presentation of an MTCProof, as defined in draft-ietf-plants-merkle-tree-certs.
 *
 * <pre>
 * struct {
 *     uint64 start;
 *     uint64 end;
 *     opaque inclusion_proof<0..2^16-1>;
 *     MTCSignature signatures<0..2^16-1>;
 * } MTCProof;
 *
 * where MTCSignature is:
 * struct {
 *     opaque cosigner_id<1..2^8-1>;
 *     opaque signature<0..2^16-1>;
 * } MTCSignature;
 * </pre>
 */
public class MTCProof
{
    private final long start;
    private final long end;
    private final byte[] inclusionProof;           // concatenated hashes
    private final List<MTCSignature> signatures;   // list of parsed signatures

    /**
     * Construct a new MTCProof from its components.
     *
     * @param start           subtree start index
     * @param end             subtree end index
     * @param inclusionProof  concatenated hash values
     * @param signatures      list of signatures (each a cosigner ID DER + raw signature)
     */
    public MTCProof(long start, long end, byte[] inclusionProof, List<MTCSignature> signatures)
    {
        this.start = start;
        this.end = end;
        this.inclusionProof = inclusionProof.clone();
        this.signatures = Collections.unmodifiableList(signatures);
    }

    /**
     * Parse an MTCProof from its TLS wire encoding.
     *
     * @param data the complete byte array
     * @throws IOException if parsing fails
     */
    public MTCProof(byte[] data) throws IOException
    {
        ByteArrayInputStream in = new ByteArrayInputStream(data);

        // start (8 bytes)
        this.start = Utils.readUint64(in);
        // end (8 bytes)
        this.end = Utils.readUint64(in);

        // inclusion_proof length (2 bytes)
        int inclLen = Utils.readUint16(in);
        this.inclusionProof = new byte[inclLen];
        if (readFully(in, inclusionProof) != inclLen)
        {
            throw new IOException("Truncated inclusion_proof");
        }

        // signatures length (2 bytes)
        int sigsLen = Utils.readUint16(in);
        byte[] sigsData = new byte[sigsLen];
        if (readFully(in, sigsData) != sigsLen)
        {
            throw new IOException("Truncated signatures data");
        }

        // Parse each signature from sigsData
        List<MTCSignature> sigList = new ArrayList<>();
        ByteArrayInputStream sigsIn = new ByteArrayInputStream(sigsData);
        while (sigsIn.available() > 0)
        {
            // cosigner_id length (1 byte)
            int idLen = sigsIn.read();
            if (idLen < 0)
            {
                throw new IOException("Truncated cosigner_id length");
            }
            if (idLen < 1)
            {
                throw new IOException("Invalid cosigner_id length: " + idLen);
            }
            byte[] cosignerId = new byte[idLen];
            if (readFully(sigsIn, cosignerId) != idLen)
            {
                throw new IOException("Truncated cosigner_id");
            }

            // signature length (2 bytes)
            int sigLen = (sigsIn.read() << 8) | sigsIn.read();
            if (sigLen < 0)
            {
                throw new IOException("Truncated signature length");
            }
            byte[] signature = new byte[sigLen];
            if (readFully(sigsIn, signature) != sigLen)
            {
                throw new IOException("Truncated signature");
            }

            // Wrap in MTCSignature (ASN.1 representation – note: cosignerId is already DER-encoded RELATIVE-OID)
            // The MTCSignature class expects the DER bytes, which we have.
            sigList.add(new MTCSignature(cosignerId, signature));
        }
        this.signatures = Collections.unmodifiableList(sigList);
    }

    /**
     * Encode this MTCProof to its TLS wire format.
     *
     * @return the encoded byte array
     * @throws IOException if encoding fails
     */
    public byte[] encode() throws IOException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        Utils.writeUint64(baos, start);
        Utils.writeUint64(baos, end);

        // inclusion_proof length and data
        Utils.writeUint16(baos, inclusionProof.length);
        baos.write(inclusionProof);

        // signatures: first encode each signature into a temporary buffer
        ByteArrayOutputStream sigsBaos = new ByteArrayOutputStream();
        for (MTCSignature sig : signatures)
        {
            byte[] cosignerId = sig.getCosignerId().getEncoded(); // DER-encoded RELATIVE-OID (tag + length + value)
            byte[] signature = sig.getSignatureValue();           // raw signature bytes

            // cosigner_id length (1 byte)
            if (cosignerId.length < 1 || cosignerId.length > 255)
            {
                throw new IOException("Invalid cosigner_id length: " + cosignerId.length);
            }
            sigsBaos.write(cosignerId.length);
            sigsBaos.write(cosignerId);

            // signature length (2 bytes)
            if (signature.length > 65535)
            {
                throw new IOException("Signature too long: " + signature.length);
            }
            Utils.writeUint16(sigsBaos, signature.length);
            sigsBaos.write(signature);
        }
        byte[] sigsBytes = sigsBaos.toByteArray();

        // Write signatures length and data
        Utils.writeUint16(baos, sigsBytes.length);
        baos.write(sigsBytes);

        return baos.toByteArray();
    }

    // Getters
    public long getStart() { return start; }
    public long getEnd() { return end; }
    public byte[] getInclusionProof() { return inclusionProof.clone(); }
    public List<MTCSignature> getSignatures() { return signatures; }

    // Helper to split inclusionProof into individual hashes given a hash size
    public List<byte[]> getHashList(int hashSize)
    {
        if (inclusionProof.length % hashSize != 0)
        {
            throw new IllegalArgumentException("Inclusion proof length not multiple of hash size");
        }
        List<byte[]> list = new ArrayList<>(inclusionProof.length / hashSize);
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
                return off; // EOF
            }
            off += count;
            len -= count;
        }
        return off;
    }
}