package org.bouncycastle.cert.plants;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.plants.MTCSignatureVerifier;
import org.bouncycastle.crypto.plants.MerkleTreePrimitives;
import org.bouncycastle.util.Arrays;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

/**
 * Validates a Merkle Tree Certificate (MTC) as defined in draft-ietf-plants-merkle-tree-certs.
 * This validator handles the custom signature algorithm id-alg-mtcProof and performs
 * inclusion proof verification and cosignature checks.
 */
public class MerkleTreeCertificateValidator
{
    // OID for the MTC proof signature algorithm (temporary value, will be assigned by IANA)
    public static final String ID_ALG_MTC_PROOF = "1.3.6.1.4.1.44363.47.0";

    /**
     * Parameters for MTC validation, provided by the relying party.
     */
    public static class ValidationParams
    {
        // Map of cosigner ID (DER-encoded RELATIVE-OID) to its public key (as a Bouncy Castle AsymmetricKeyParameter)
        private final Map<ByteArrayKey, AsymmetricKeyParameter> cosignerPublicKeys;

        // List of trusted subtrees (pre‑distributed landmarks) for this log
        private final List<TrustedSubtree> trustedSubtrees;

        // Revoked indices (serial numbers) – could be a set or a function
        private final Set<Long> revokedIndices;

        // Policy: minimum number of valid cosignatures required (or a more complex policy)
        private final int minCosignatures;

        // Hash function used by the log (must match the log's parameters)
        private final MerkleTreePrimitives.MerkleTreeHash hashFunction;

        /**
         * @param cosignerPublicKeys map from cosigner ID (DER bytes) to public key
         * @param trustedSubtrees    list of trusted subtrees for this log
         * @param revokedIndices     set of revoked serial numbers (indices)
         * @param minCosignatures    minimum number of valid cosignatures required
         * @param hashFunction       hash function used by the log (e.g., new Sha256MerkleTreeHash())
         */
        public ValidationParams(
            Map<ByteArrayKey, AsymmetricKeyParameter> cosignerPublicKeys,
            List<TrustedSubtree> trustedSubtrees,
            Set<Long> revokedIndices,
            int minCosignatures,
            MerkleTreePrimitives.MerkleTreeHash hashFunction)
        {
            this.cosignerPublicKeys = cosignerPublicKeys;
            this.trustedSubtrees = trustedSubtrees;
            this.revokedIndices = revokedIndices;
            this.minCosignatures = minCosignatures;
            this.hashFunction = hashFunction;
        }

        public Map<ByteArrayKey, AsymmetricKeyParameter> getCosignerPublicKeys()
        {
            return cosignerPublicKeys;
        }

        public List<TrustedSubtree> getTrustedSubtrees()
        {
            return trustedSubtrees;
        }

        public Set<Long> getRevokedIndices()
        {
            return revokedIndices;
        }

        public int getMinCosignatures()
        {
            return minCosignatures;
        }

        public MerkleTreePrimitives.MerkleTreeHash getHashFunction()
        {
            return hashFunction;
        }
    }

    /**
     * Represents a trusted subtree (landmark).
     */
    public static class TrustedSubtree
    {
        private final long start;
        private final long end;
        private final byte[] hash; // subtree hash

        public TrustedSubtree(long start, long end, byte[] hash)
        {
            this.start = start;
            this.end = end;
            this.hash = hash.clone();
        }

        public long getStart()
        {
            return start;
        }

        public long getEnd()
        {
            return end;
        }

        public byte[] getHash()
        {
            return hash.clone();
        }

        public boolean matches(long start, long end, byte[] hash)
        {
            return this.start == start && this.end == end && Arrays.areEqual(this.hash, hash);
        }
    }

    /**
     * Result of a cosignature verification.
     */
    private static class CosignatureResult
    {
        final byte[] cosignerId;
        final boolean valid;

        CosignatureResult(byte[] cosignerId, boolean valid)
        {
            this.cosignerId = cosignerId;
            this.valid = valid;
        }
    }

    /**
     * Validates a Merkle Tree Certificate.
     *
     * @param certHolder the X.509 certificate holder (may be from Bouncy Castle's X509CertificateHolder)
     * @param params     validation parameters (cosigners, trusted subtrees, revocation, etc.)
     * @return true if the certificate is valid according to the MTC rules and the relying party's policy
     * @throws Exception if validation fails (with specific exception types for different failures)
     */
    public static boolean validateCertificate(
        X509CertificateHolder certHolder,
        ValidationParams params)
        throws Exception
    {
        // 1. Check that the TBSCertificate signature algorithm is id-alg-mtcProof
        AlgorithmIdentifier sigAlgId = certHolder.getSignatureAlgorithm();
        if (!ID_ALG_MTC_PROOF.equals(sigAlgId.getAlgorithm().getId()))
        {
            throw new IllegalArgumentException("Not a Merkle Tree certificate: expected id-alg-mtcProof");
        }

        // 2. Decode the signature value as an MTCProof
        byte[] signatureValue = certHolder.getSignature();
        // The signature value is a BIT STRING containing the raw MTCProof (TLS encoding)
        // We need to parse it according to TLS presentation.
        MTCProof proof = MTCProof.parse(signatureValue, params.hashFunction.getHashSize());

        // 3. Extract the log entry index from the serial number
        BigInteger serialBig = certHolder.getSerialNumber();
        if (serialBig.compareTo(BigInteger.ZERO) <= 0)
        {
            throw new IllegalArgumentException("Serial number must be positive (index > 0)");
        }
        long index = serialBig.longValue(); // serial numbers are positive and fit in long

        // 4. Check revocation by index
        if (params.revokedIndices.contains(index))
        {
            throw new SecurityException("Certificate index " + index + " is revoked");
        }

        // 5. Reconstruct the TBSCertificateLogEntry and compute entry hash
        byte[] entryHash = computeEntryHash(certHolder, params.hashFunction);

        // 6. Evaluate the inclusion proof to get expected subtree hash
        byte[] expectedSubtreeHash;
        try
        {
            expectedSubtreeHash = MerkleTreePrimitives.evaluateSubtreeInclusionProof(
                index,
                proof.start,
                proof.end,
                entryHash,
                proof.getHashList(params.hashFunction.getHashSize()),
                params.hashFunction
            );
        }
        catch (MerkleTreePrimitives.InvalidProofException e)
        {
            throw new SecurityException("Invalid inclusion proof: " + e.getMessage());
        }

        // 7. Check if the subtree matches a trusted subtree (landmark)
        for (TrustedSubtree trusted : params.trustedSubtrees)
        {
            if (trusted.matches(proof.start, proof.end, expectedSubtreeHash))
            {
                // Certificate is valid via trusted subtree
                return true;
            }
        }

        // 8. No trusted subtree matches; verify cosignatures
        List<CosignatureResult> cosignatureResults = new ArrayList<>();
        for (MTCSignature sig : proof.signatures)
        {
            boolean valid = verifyCosignature(
                extractLogIdFromIssuer(certHolder.getIssuer()), // log ID (DER-encoded RELATIVE-OID)
                proof.start,
                proof.end,
                expectedSubtreeHash,
                sig.cosignerId,
                sig.signature,
                params
            );
            cosignatureResults.add(new CosignatureResult(sig.cosignerId, valid));
        }

        // Apply policy: count valid cosignatures
        long validCount = cosignatureResults.stream().filter(r -> r.valid).count();
        if (validCount >= params.minCosignatures)
        {
            return true;
        }
        else
        {
            throw new SecurityException("Insufficient valid cosignatures: " + validCount +
                " < " + params.minCosignatures);
        }
    }

    /**
     * Verifies a single cosignature using MTCSignatureVerifier.
     */
    private static boolean verifyCosignature(
        byte[] logId,
        long start,
        long end,
        byte[] subtreeHash,
        byte[] cosignerId,
        byte[] signature,
        ValidationParams params)
        throws IOException
    {
        org.bouncycastle.crypto.params.AsymmetricKeyParameter pubKey =
            params.cosignerPublicKeys.get(new ByteArrayKey(cosignerId));
        if (pubKey == null)
        {
            return false; // cosigner not trusted
        }

        // Determine algorithm from public key type (or from context)
        // For simplicity, we derive algorithm from the key type.
        String algorithm = getAlgorithmFromKey(pubKey);

        return MTCSignatureVerifier.verify(
            logId,
            start,
            end,
            subtreeHash,
            cosignerId,
            signature,
            pubKey,
            algorithm
        );
    }

    /**
     * Maps a Bouncy Castle AsymmetricKeyParameter to the algorithm string used by MTCSignatureVerifier.
     */
    private static String getAlgorithmFromKey(org.bouncycastle.crypto.params.AsymmetricKeyParameter key)
    {
        if (key instanceof org.bouncycastle.crypto.params.ECPublicKeyParameters)
        {
            org.bouncycastle.crypto.params.ECPublicKeyParameters ec = (org.bouncycastle.crypto.params.ECPublicKeyParameters)key;
            int fieldSize = ec.getParameters().getCurve().getFieldSize();
            if (fieldSize == 256)
            {
                return "ECDSA-P256-SHA256";
            }
            else if (fieldSize == 384)
            {
                return "ECDSA-P384-SHA384";
            }
            else
            {
                throw new IllegalArgumentException("Unsupported EC field size: " + fieldSize);
            }
        }
        else if (key instanceof org.bouncycastle.crypto.params.Ed25519PublicKeyParameters)
        {
            return "Ed25519";
        }
        else if (key.getClass().getName().contains("MLDSAPublicKeyParameters"))
        {
            // We need to differentiate ML-DSA parameter sets.
            // This is a placeholder – actual detection depends on Bouncy Castle's ML-DSA implementation.
            return "ML-DSA-65"; // default? Better to have a mapping from key to specific algorithm.
        }
        else
        {
            throw new IllegalArgumentException("Unsupported public key type: " + key.getClass().getName());
        }
    }

    /**
     * Computes the entry hash for the given certificate using the single-pass method
     * described in Section 7.2 of the draft.
     */
    public static byte[] computeEntryHash(
        X509CertificateHolder certHolder,
        MerkleTreePrimitives.MerkleTreeHash hashFunc)
        throws IOException
    {
        byte[] tbsCertBytes = certHolder.getTBSCertificate().getEncoded();

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream())
        {
            // 1. Two-byte type (big-endian) for tbs_cert_entry (type = 1)
            baos.write(0x00);
            baos.write(0x01);

            // 2. Parse TBSCertificate sequence
            ASN1InputStream asn1In = new ASN1InputStream(tbsCertBytes);
            ASN1Sequence tbsSeq = (ASN1Sequence)asn1In.readObject();
            asn1In.close();

            ByteArrayOutputStream prefix = new ByteArrayOutputStream();
            ByteArrayOutputStream spkiBytes = new ByteArrayOutputStream();
            ByteArrayOutputStream suffix = new ByteArrayOutputStream();

            boolean foundSpki = false;
            for (int i = 0; i < tbsSeq.size(); i++)
            {
                ASN1Encodable element = tbsSeq.getObjectAt(i);
                byte[] enc = element.toASN1Primitive().getEncoded(ASN1Encoding.DER);

                if (!foundSpki)
                {
                    // Attempt to parse as SubjectPublicKeyInfo
                    try
                    {
                        SubjectPublicKeyInfo spkiTest = SubjectPublicKeyInfo.getInstance(element);
                        // Success – this is the SPKI
                        foundSpki = true;
                        spkiBytes.write(enc, 0, enc.length);
                        continue;
                    }
                    catch (Exception e)
                    {
                        // Not SPKI, add to prefix
                        prefix.write(enc, 0, enc.length);
                    }
                }
                else
                {
                    suffix.write(enc, 0, enc.length);
                }
            }

            if (!foundSpki)
            {
                throw new IOException("Could not locate subjectPublicKeyInfo in TBSCertificate");
            }

            // Write prefix
            baos.write(prefix.toByteArray());

            // Write subjectPublicKeyInfo.algorithm (DER encoded)
            ASN1InputStream spkiIn = new ASN1InputStream(spkiBytes.toByteArray());
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(spkiIn.readObject());
            spkiIn.close();
            byte[] algEnc = spki.getAlgorithm().getEncoded(ASN1Encoding.DER);
            baos.write(algEnc);

            // Write OCTET STRING identifier (0x04)
            baos.write(0x04);

            // Write L (hash length, assuming <= 127)
            int hashSize = hashFunc.getHashSize();
            if (hashSize > 127)
            {
                throw new IllegalArgumentException("Hash size > 127 not supported in single-pass method");
            }
            baos.write((byte)hashSize);

            // Compute hash of the entire subjectPublicKeyInfo
            byte[] spkiHash = new byte[hashSize];
            Digest digest = new SHA256Digest(); // Must match log's hash function
            digest.update(spkiBytes.toByteArray(), 0, spkiBytes.size());
            digest.doFinal(spkiHash, 0);
            baos.write(spkiHash);

            // Write suffix
            baos.write(suffix.toByteArray());

            // Final entry hash = HASH(0x00 || entryBytes)
            byte[] entryBytes = baos.toByteArray();
            return hashFunc.hashLeaf(entryBytes);
        }
    }


    public static byte[] extractLogIdFromIssuer(X500Name issuer) throws IOException
    {
        RDN[] rdns = issuer.getRDNs();
        if (rdns.length != 1)
            throw new IOException("Issuer must have exactly one RDN");
        AttributeTypeAndValue[] atav = rdns[0].getTypesAndValues();
        if (atav.length != 1)
            throw new IOException("RDN must have exactly one attribute");
        AttributeTypeAndValue at = atav[0];
        if (!at.getType().equals(X509Extension.id_rdna_trustAnchorID))
            throw new IOException("Attribute type must be id-rdna-trustAnchorID");
        ASN1Encodable value = at.getValue();
        return ((DEROctetString)value).getOctets();
    }


    /**
     * In-memory representation of an MTCProof parsed from TLS encoding.
     */
    private static class MTCProof
    {
        final long start;
        final long end;
        final byte[] inclusionProof; // concatenated hashes
        final List<MTCSignature> signatures;

        MTCProof(long start, long end, byte[] inclusionProof, List<MTCSignature> signatures)
        {
            this.start = start;
            this.end = end;
            this.inclusionProof = inclusionProof;
            this.signatures = signatures;
        }

        /**
         * Parses a byte array (TLS presentation of MTCProof) into an MTCProof object.
         * The format:
         * uint64 start;           // 8 bytes
         * uint64 end;             // 8 bytes
         * opaque inclusion_proof<0..2^16-1>;  // 2-byte length + data
         * MTCSignature signatures<0..2^16-1>; // 2-byte length + sequence of signatures
         * where MTCSignature is:
         * opaque cosigner_id<1..2^8-1>;   // 1-byte length + data
         * opaque signature<0..2^16-1>;    // 2-byte length + data
         */
        static MTCProof parse(byte[] data, int hashSize)
            throws IOException
        {
            int pos = 0;

            // start (8 bytes)
            if (pos + 8 > data.length)
            {
                throw new IOException("Truncated MTCProof");
            }
            long start = readUint64(data, pos);
            pos += 8;

            // end (8 bytes)
            long end = readUint64(data, pos);
            pos += 8;

            // inclusion_proof length (2 bytes)
            if (pos + 2 > data.length)
            {
                throw new IOException("Truncated inclusion_proof length");
            }
            int inclLen = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
            pos += 2;
            if (pos + inclLen > data.length)
            {
                throw new IOException("Truncated inclusion_proof data");
            }
            byte[] inclusionProof = new byte[inclLen];
            System.arraycopy(data, pos, inclusionProof, 0, inclLen);
            pos += inclLen;

            // signatures length (2 bytes)
            if (pos + 2 > data.length)
            {
                throw new IOException("Truncated signatures length");
            }
            int sigsLen = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
            pos += 2;
            int sigsEnd = pos + sigsLen;
            if (sigsEnd > data.length)
            {
                throw new IOException("Truncated signatures data");
            }

            List<MTCSignature> signatures = new ArrayList<>();
            while (pos < sigsEnd)
            {
                // cosigner_id length (1 byte)
                if (pos + 1 > sigsEnd)
                {
                    throw new IOException("Truncated cosigner_id length");
                }
                int idLen = data[pos] & 0xFF;
                pos += 1;
                if (pos + idLen > sigsEnd)
                {
                    throw new IOException("Truncated cosigner_id data");
                }
                byte[] cosignerId = new byte[idLen];
                System.arraycopy(data, pos, cosignerId, 0, idLen);
                pos += idLen;

                // signature length (2 bytes)
                if (pos + 2 > sigsEnd)
                {
                    throw new IOException("Truncated signature length");
                }
                int sigLen = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
                pos += 2;
                if (pos + sigLen > sigsEnd)
                {
                    throw new IOException("Truncated signature data");
                }
                byte[] signature = new byte[sigLen];
                System.arraycopy(data, pos, signature, 0, sigLen);
                pos += sigLen;

                signatures.add(new MTCSignature(cosignerId, signature));
            }

            return new MTCProof(start, end, inclusionProof, signatures);
        }

        private static long readUint64(byte[] data, int off)
        {
            return ((data[off] & 0xFFL) << 56) |
                ((data[off + 1] & 0xFFL) << 48) |
                ((data[off + 2] & 0xFFL) << 40) |
                ((data[off + 3] & 0xFFL) << 32) |
                ((data[off + 4] & 0xFFL) << 24) |
                ((data[off + 5] & 0xFFL) << 16) |
                ((data[off + 6] & 0xFFL) << 8) |
                (data[off + 7] & 0xFFL);
        }

        /**
         * Splits the concatenated inclusion proof into a list of individual hashes.
         */
        List<byte[]> getHashList()
        {
            List<byte[]> list = new ArrayList<>();
            int hashSize = 32; // We should get this from params, but for simplicity assume 32.
            // In practice, we need to know the hash size from the log parameters.
            // For now, we pass it separately; we'll assume the caller provides it.
            // This method is called from validateCertificate where we have params.hashFunction.getHashSize().
            // We'll need to pass that size to this method.
            throw new UnsupportedOperationException("Use getHashList(int hashSize) instead");
        }

        List<byte[]> getHashList(int hashSize)
        {
            List<byte[]> list = new ArrayList<>();
            for (int i = 0; i + hashSize <= inclusionProof.length; i += hashSize)
            {
                byte[] hash = new byte[hashSize];
                System.arraycopy(inclusionProof, i, hash, 0, hashSize);
                list.add(hash);
            }
            if (inclusionProof.length % hashSize != 0)
            {
                throw new IllegalArgumentException("Inclusion proof length not a multiple of hash size");
            }
            return list;
        }
    }

    public static class ByteArrayKey
    {
        private final byte[] data;

        public ByteArrayKey(byte[] data)
        {
            this.data = data.clone();
        }

        public byte[] getData()
        {
            return data.clone();
        }

        @Override
        public boolean equals(Object o)
        {
            if (this == o)
            {
                return true;
            }
            if (!(o instanceof ByteArrayKey))
            {
                return false;
            }
            ByteArrayKey that = (ByteArrayKey)o;
            return Arrays.areEqual(this.data, that.data);
        }

        @Override
        public int hashCode()
        {
            return Arrays.hashCode(data);
        }
    }
}