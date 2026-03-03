package org.bouncycastle.cert.plants;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.plants.MTCSignatureVerifier;
import org.bouncycastle.crypto.plants.MerkleTreePrimitives;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

/**
 * Handles landmark certificates and trusted subtrees as defined in
 * draft-ietf-plants-merkle-tree-certs, Sections 6.3 and 7.4.
 */
public class LandmarkCertificateManager
{
    /**
     * Builds a landmark certificate for a given log entry and landmark.
     *
     * @param logId                the log ID (DER-encoded RELATIVE-OID)
     * @param index                the index of the entry in the log
     * @param tbsCertEntry         the TBSCertificateLogEntry (ASN.1 structure)
     * @param subjectPublicKeyInfo the actual SubjectPublicKeyInfo (DER-encoded)
     * @param landmarkNumber       the landmark number (L)
     * @param baseId               base OID for the landmark sequence
     * @param landmarkSubtree      the chosen landmark subtree that contains the entry
     * @param inclusionProof       list of node hashes forming the inclusion proof
     * @param hashFunc             the hash function used by the log
     * @return an X.509 Certificate (as a byte array or holder) containing the landmark certificate
     * @throws IOException if encoding fails
     */
    public static X509CertificateHolder buildLandmarkCertificate(
        byte[] logId,
        long index,
        TBSCertificateLogEntry tbsCertEntry,
        SubjectPublicKeyInfo subjectPublicKeyInfo,
        long landmarkNumber,
        ASN1ObjectIdentifier baseId,
        MerkleTreePrimitives.SubtreeInfo landmarkSubtree,
        List<byte[]> inclusionProof,
        MerkleTreePrimitives.MerkleTreeHash hashFunc)
        throws IOException
    {
        // 1. Build the TBSCertificate according to Section 6.1
        //    - version, issuer, validity, subject, etc. from tbsCertEntry
        //    - serialNumber = index
        //    - subjectPublicKeyInfo = provided
        //    - signature algorithm = id-alg-mtcProof

        TBSCertificateStructure tbs = buildTBSCertificate(
            tbsCertEntry, index, subjectPublicKeyInfo);

        // 2. Construct the MTCProof for a landmark certificate (no signatures)
        //    - start, end from landmarkSubtree
        //    - inclusion_proof = concatenated hashes
        //    - signatures = empty list

        byte[] inclusionProofBytes = concatenateHashes(inclusionProof, hashFunc.getHashSize());
        MTCProof proof = new MTCProof(
            landmarkSubtree.getStart(),
            landmarkSubtree.getEnd(),
            inclusionProofBytes,
            Collections.emptyList() // no signatures
        );

        // 3. Encode the MTCProof as a byte array (TLS presentation)
        byte[] proofEncoded = proof.encode();

        // 4. Build the final Certificate:
        //    - TBSCertificate as built
        //    - signatureAlgorithm = id-alg-mtcProof (AlgorithmIdentifier with null parameters)
        //    - signatureValue = BIT STRING containing proofEncoded

        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(
            new ASN1ObjectIdentifier(MerkleTreeCertificateValidator.ID_ALG_MTC_PROOF));

        DERBitString signature = new DERBitString(proofEncoded);

        X509CertificateHolder cert = new X509CertificateHolder(
            new DERSequence(new ASN1Encodable[]{
                tbs.toASN1Primitive(),
                sigAlg,
                signature
            }).getEncoded());

        return cert;
    }

    private static TBSCertificateStructure buildTBSCertificate(
        TBSCertificateLogEntry tbsEntry,
        long index,
        SubjectPublicKeyInfo subjectPublicKeyInfo)
        throws IOException
    {
        // Construct TBSCertificate according to Section 6.1
        // Fields from tbsEntry: version, issuer, validity, subject, extensions, uniqueIDs
        // serialNumber = ASN1Integer(index)
        // subjectPublicKeyInfo = provided
        // signature = id-alg-mtcProof (the algorithm identifier, not the proof itself)
        // issuerUniqueID, subjectUniqueID, extensions if present

        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(
            new ASN1ObjectIdentifier(MerkleTreeCertificateValidator.ID_ALG_MTC_PROOF));

        ASN1EncodableVector v = new ASN1EncodableVector();

        // version (explicit tag [0]) if not default v1 (v1 = 0)
        if (tbsEntry.getVersion() != null && tbsEntry.getVersion().getValue().intValue() != 0)
        {
            v.add(new DERTaggedObject(true, 0, tbsEntry.getVersion()));
        }

        v.add(new ASN1Integer(index));                     // serialNumber
        v.add(sigAlg);                                      // signature (algorithm)
        v.add(tbsEntry.getIssuer());                        // issuer
        v.add(tbsEntry.getValidity());                      // validity
        v.add(tbsEntry.getSubject());                       // subject
        v.add(subjectPublicKeyInfo);                         // subjectPublicKeyInfo

        if (tbsEntry.getIssuerUniqueID() != null)
        {
            v.add(new DERTaggedObject(false, 1, tbsEntry.getIssuerUniqueID()));
        }
        if (tbsEntry.getSubjectUniqueID() != null)
        {
            v.add(new DERTaggedObject(false, 2, tbsEntry.getSubjectUniqueID()));
        }
        if (tbsEntry.getExtensions() != null)
        {
            v.add(new DERTaggedObject(true, 3, tbsEntry.getExtensions()));
        }

        return TBSCertificateStructure.getInstance(new DERSequence(v));
    }

    private static byte[] concatenateHashes(List<byte[]> hashes, int hashSize)
    {
        byte[] result = new byte[hashes.size() * hashSize];
        int off = 0;
        for (byte[] h : hashes)
        {
            System.arraycopy(h, 0, result, off, hashSize);
            off += hashSize;
        }
        return result;
    }

    // ----------------------------------------------------------------------
    // Trusted Subtree Management (Section 7.4)
    // ----------------------------------------------------------------------

    /**
     * Represents a trusted subtree (landmark) along with the checkpoint that proves its consistency.
     */
    public static class TrustedSubtreeEntry
    {
        private final long start;
        private final long end;
        private final byte[] hash;                 // subtree hash
        private final long checkpointTreeSize;      // tree size of the checkpoint that proves consistency
        private final byte[] checkpointRootHash;    // root hash of that checkpoint

        public TrustedSubtreeEntry(long start, long end, byte[] hash,
                                   long checkpointTreeSize, byte[] checkpointRootHash)
        {
            this.start = start;
            this.end = end;
            this.hash = hash.clone();
            this.checkpointTreeSize = checkpointTreeSize;
            this.checkpointRootHash = checkpointRootHash.clone();
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

        public long getCheckpointTreeSize()
        {
            return checkpointTreeSize;
        }

        public byte[] getCheckpointRootHash()
        {
            return checkpointRootHash.clone();
        }

        public boolean matches(long start, long end, byte[] hash)
        {
            return this.start == start && this.end == end && Arrays.areEqual(this.hash, hash);
        }
    }

    /**
     * Manages a list of trusted subtrees for a log. Provides methods to add new landmarks
     * after verifying consistency with cosigned checkpoints.
     */
    public static class TrustedSubtreeManager
    {
        private final byte[] logId;
        private final MerkleTreePrimitives.MerkleTreeHash hashFunc;
        private final Map<byte[], org.bouncycastle.crypto.params.AsymmetricKeyParameter> cosignerPublicKeys;
        private final int minCosignaturesForCheckpoint;

        // Current trusted subtrees (landmarks)
        private final List<TrustedSubtreeEntry> trustedSubtrees = new ArrayList<>();

        /**
         * @param logId                        log ID (DER-encoded RELATIVE-OID)
         * @param hashFunc                     hash function used by the log
         * @param cosignerPublicKeys           map from cosigner ID to public key
         * @param minCosignaturesForCheckpoint minimum number of valid cosignatures required to trust a checkpoint
         */
        public TrustedSubtreeManager(
            byte[] logId,
            MerkleTreePrimitives.MerkleTreeHash hashFunc,
            Map<byte[], org.bouncycastle.crypto.params.AsymmetricKeyParameter> cosignerPublicKeys,
            int minCosignaturesForCheckpoint)
        {
            this.logId = logId.clone();
            this.hashFunc = hashFunc;
            this.cosignerPublicKeys = cosignerPublicKeys;
            this.minCosignaturesForCheckpoint = minCosignaturesForCheckpoint;
        }

        /**
         * Returns an unmodifiable view of the current trusted subtrees.
         */
        public List<TrustedSubtreeEntry> getTrustedSubtrees()
        {
            return Collections.unmodifiableList(trustedSubtrees);
        }

        /**
         * Attempts to add a new landmark subtree.
         *
         * @param subtreeStart         start index of the new subtree
         * @param subtreeEnd           end index of the new subtree
         * @param subtreeHash          hash of the subtree
         * @param referenceCheckpoint  a checkpoint that contains the subtree (must be cosigned)
         * @param consistencyProof     subtree consistency proof from the subtree to the checkpoint
         * @param checkpointSignatures list of (cosignerId, signature) over the checkpoint
         * @return true if the subtree was added successfully, false otherwise
         */
        public boolean addLandmarkSubtree(
            long subtreeStart,
            long subtreeEnd,
            byte[] subtreeHash,
            Checkpoint referenceCheckpoint,
            List<byte[]> consistencyProof,
            List<MTCSignature> checkpointSignatures)
        {
            // 1. Verify the checkpoint is signed by enough trusted cosigners
            if (!verifyCheckpointSignatures(referenceCheckpoint, checkpointSignatures))
            {
                return false;
            }

            // 2. Verify subtree consistency with the checkpoint
            if (!verifySubtreeConsistency(
                subtreeStart, subtreeEnd, subtreeHash,
                referenceCheckpoint.treeSize, referenceCheckpoint.rootHash,
                consistencyProof))
            {
                return false;
            }

            // 3. Add to trusted list (optionally prune old landmarks)
            trustedSubtrees.add(new TrustedSubtreeEntry(
                subtreeStart, subtreeEnd, subtreeHash,
                referenceCheckpoint.treeSize, referenceCheckpoint.rootHash));

            // Optionally, keep only the most recent max_landmarks entries.
            // (Not implemented here; caller can manage.)

            return true;
        }

        /**
         * Verifies that a checkpoint is signed by a sufficient set of trusted cosigners.
         */
        private boolean verifyCheckpointSignatures(
            Checkpoint checkpoint,
            List<MTCSignature> signatures)
        {
            int valid = 0;
            for (MTCSignature sig : signatures)
            {
                org.bouncycastle.crypto.params.AsymmetricKeyParameter pubKey =
                    cosignerPublicKeys.get(sig.cosignerId);
                if (pubKey == null)
                {
                    continue;
                }

                // Build checkpoint signature input
                // For checkpoints, the draft says: "When start is zero, the resulting signature describes the checkpoint."
                // The signature input for a checkpoint uses the same structure but with start=0.
                // We'll reuse MTCSignatureVerifier with start=0 and the checkpoint root hash as subtreeHash.
                byte[] signedData = buildCheckpointSignatureInput(
                    logId,
                    0,
                    checkpoint.treeSize,
                    checkpoint.rootHash,
                    sig.cosignerId
                );

                // Determine algorithm from key type
                String algorithm = getAlgorithmFromKey(pubKey);

                boolean ok = MTCSignatureVerifier.verify(
                    logId,
                    0,
                    checkpoint.treeSize,
                    checkpoint.rootHash,
                    sig.cosignerId,
                    sig.signature,
                    pubKey,
                    algorithm
                );
                if (ok)
                {
                    valid++;
                }
            }
            return valid >= minCosignaturesForCheckpoint;
        }

        /**
         * Builds signature input for a checkpoint (start=0).
         */
        private byte[] buildCheckpointSignatureInput(
            byte[] logId,
            long start,
            long end,
            byte[] rootHash,
            byte[] cosignerId)
        {
            try (ByteArrayOutputStream baos = new ByteArrayOutputStream())
            {
                // Fixed label (same as subtree, but domain separation is via the label itself)
                baos.write("mtc-subtree/v1\n\0".getBytes("ASCII")); // 16 bytes

                // cosigner_id
                baos.write((byte)cosignerId.length);
                baos.write(cosignerId);

                // log_id
                baos.write((byte)logId.length);
                baos.write(logId);

                // start (uint64)
                writeUint64(baos, start);
                // end (uint64)
                writeUint64(baos, end);
                // rootHash
                baos.write(rootHash);

                return baos.toByteArray();
            }
            catch (IOException e)
            {
                throw new RuntimeException(e);
            }
        }

        private void writeUint64(ByteArrayOutputStream baos, long v)
        {
            baos.write((byte)(v >>> 56));
            baos.write((byte)(v >>> 48));
            baos.write((byte)(v >>> 40));
            baos.write((byte)(v >>> 32));
            baos.write((byte)(v >>> 24));
            baos.write((byte)(v >>> 16));
            baos.write((byte)(v >>> 8));
            baos.write((byte)v);
        }

        private String getAlgorithmFromKey(org.bouncycastle.crypto.params.AsymmetricKeyParameter key)
        {
            if (key instanceof org.bouncycastle.crypto.params.ECPublicKeyParameters)
            {
                org.bouncycastle.crypto.params.ECPublicKeyParameters ec = (org.bouncycastle.crypto.params.ECPublicKeyParameters)key;
                int fieldSize = ec.getParameters().getCurve().getFieldSize();
                if (fieldSize == 256)
                {
                    return "ECDSA-P256-SHA256";
                }
                if (fieldSize == 384)
                {
                    return "ECDSA-P384-SHA384";
                }
            }
            else if (key instanceof org.bouncycastle.crypto.params.Ed25519PublicKeyParameters)
            {
                return "Ed25519";
            }
            // Add ML-DSA when available
            return null;
        }

        private boolean verifySubtreeConsistency(
            long start, long end, byte[] subtreeHash,
            long checkpointTreeSize, byte[] checkpointRootHash,
            List<byte[]> consistencyProof)
        {
            return MerkleTreePrimitives.verifySubtreeConsistencyProof(
                start, end, checkpointTreeSize,
                subtreeHash, checkpointRootHash,
                consistencyProof, hashFunc);
        }

        /**
         * Simple container for a checkpoint (tree size and root hash).
         */
        public static class Checkpoint
        {
            public final long treeSize;
            public final byte[] rootHash;

            public Checkpoint(long treeSize, byte[] rootHash)
            {
                this.treeSize = treeSize;
                this.rootHash = rootHash.clone();
            }
        }
    }

    // ----------------------------------------------------------------------
    // Helper: MTCProof encoding (simplified)
    // ----------------------------------------------------------------------
    private static class MTCProof
    {
        final long start;
        final long end;
        final byte[] inclusionProof;
        final List<MTCSignature> signatures;

        MTCProof(long start, long end, byte[] inclusionProof, List<MTCSignature> signatures)
        {
            this.start = start;
            this.end = end;
            this.inclusionProof = inclusionProof;
            this.signatures = signatures;
        }

        byte[] encode()
            throws IOException
        {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            writeUint64(baos, start);
            writeUint64(baos, end);
            // inclusion_proof length (2 bytes)
            baos.write((byte)(inclusionProof.length >>> 8));
            baos.write((byte)inclusionProof.length);
            baos.write(inclusionProof);
            // signatures length (2 bytes)
            ByteArrayOutputStream sigsBaos = new ByteArrayOutputStream();
            for (MTCSignature sig : signatures)
            {
                // cosigner_id length
                sigsBaos.write((byte)sig.cosignerId.length);
                sigsBaos.write(sig.cosignerId);
                // signature length
                sigsBaos.write((byte)(sig.signature.length >>> 8));
                sigsBaos.write((byte)sig.signature.length);
                sigsBaos.write(sig.signature);
            }
            byte[] sigsBytes = sigsBaos.toByteArray();
            baos.write((byte)(sigsBytes.length >>> 8));
            baos.write((byte)sigsBytes.length);
            baos.write(sigsBytes);
            return baos.toByteArray();
        }

        private void writeUint64(ByteArrayOutputStream baos, long v)
        {
            baos.write((byte)(v >>> 56));
            baos.write((byte)(v >>> 48));
            baos.write((byte)(v >>> 40));
            baos.write((byte)(v >>> 32));
            baos.write((byte)(v >>> 24));
            baos.write((byte)(v >>> 16));
            baos.write((byte)(v >>> 8));
            baos.write((byte)v);
        }
    }

    private static class MTCSignature
    {
        final byte[] cosignerId;
        final byte[] signature;

        MTCSignature(byte[] cosignerId, byte[] signature)
        {
            this.cosignerId = cosignerId;
            this.signature = signature;
        }
    }
}