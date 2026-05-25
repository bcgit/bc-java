package org.bouncycastle.cert.plants;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.plants.MTCObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.TBSCertificateLogEntry;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Arrays;

/**
 * Issuance- and relying-party-side helpers for landmark subtrees, per
 * Sections 6.3 and 7.4 of draft-ietf-plants-merkle-tree-certs.
 *
 * <p>{@link #buildLandmarkCertificate} produces a landmark-relative
 * certificate (an X.509 wrapper around an {@link MTCProof} whose inclusion
 * proof targets a predistributed landmark subtree). The nested
 * {@link TrustedSubtreeManager} maintains a relying party's set of
 * {@link TrustedSubtreeEntry trusted landmarks}, accepting a new landmark
 * once it has been related to a sufficiently-cosigned reference checkpoint
 * via a subtree consistency proof.</p>
 */
public class LandmarkCertificateManager
{
    /**
     * Builds a landmark-relative certificate (no signatures, only an inclusion
     * proof to a predistributed landmark subtree).
     *
     * @param index                the entry's index in the log (used as the certificate serial number)
     * @param tbsCertEntry         the TBSCertificateLogEntry describing the entry
     * @param subjectPublicKeyInfo the actual subject public key (its hash must match tbsCertEntry.subjectPublicKeyInfoHash)
     * @param landmarkSubtree      the landmark subtree containing the entry
     * @param inclusionProof       inclusion proof hashes from the entry to landmarkSubtree
     * @param hashFunc             the log's hash function
     * @return the landmark-relative certificate
     */
    public static X509CertificateHolder buildLandmarkCertificate(
        long index,
        TBSCertificateLogEntry tbsCertEntry,
        SubjectPublicKeyInfo subjectPublicKeyInfo,
        MerkleTreePrimitives.SubtreeInfo landmarkSubtree,
        List<byte[]> inclusionProof,
        MerkleTreeHash hashFunc)
        throws IOException
    {
        TBSCertificate tbs = buildTBSCertificate(tbsCertEntry, index, subjectPublicKeyInfo);

        byte[] inclusionProofBytes = concatenateHashes(inclusionProof, hashFunc.getHashSize());
        MTCProof proof = new MTCProof(
            landmarkSubtree.getStart(),
            landmarkSubtree.getEnd(),
            inclusionProofBytes,
            Collections.<MTCSignature>emptyList());

        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof);
        DERBitString signature = new DERBitString(proof.encode());

        return new X509CertificateHolder(
            new DERSequence(new ASN1Encodable[]{tbs.toASN1Primitive(), sigAlg, signature}).getEncoded());
    }

    private static TBSCertificate buildTBSCertificate(
        TBSCertificateLogEntry tbsEntry,
        long index,
        SubjectPublicKeyInfo subjectPublicKeyInfo)
    {
        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof);

        ASN1EncodableVector v = new ASN1EncodableVector();

        if (tbsEntry.getVersion() != null && tbsEntry.getVersion().getValue().intValue() != 0)
        {
            v.add(new DERTaggedObject(true, 0, tbsEntry.getVersion()));
        }

        v.add(new ASN1Integer(index));
        v.add(sigAlg);
        v.add(tbsEntry.getIssuer());
        v.add(tbsEntry.getValidity());
        v.add(tbsEntry.getSubject());
        v.add(subjectPublicKeyInfo);

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

        return TBSCertificate.getInstance(new DERSequence(v));
    }

    private static byte[] concatenateHashes(List<byte[]> hashes, int hashSize)
    {
        byte[] result = new byte[hashes.size() * hashSize];
        int off = 0;
        for (byte[] h : hashes)
        {
            if (h.length != hashSize)
            {
                throw new IllegalArgumentException("Hash size mismatch: expected " + hashSize + ", got " + h.length);
            }
            System.arraycopy(h, 0, result, off, hashSize);
            off += hashSize;
        }
        return result;
    }

    /**
     * A trusted subtree along with the reference checkpoint that proved its
     * consistency, per Section 7.4.
     */
    public static class TrustedSubtreeEntry
    {
        private final long start;
        private final long end;
        private final byte[] hash;
        private final long checkpointTreeSize;
        private final byte[] checkpointRootHash;

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
     * Maintains a relying-party-side list of trusted subtrees by accepting new
     * landmarks that come with a cosigned reference checkpoint and a subtree
     * consistency proof.
     */
    public static class TrustedSubtreeManager
    {
        private final byte[] logId;
        private final MerkleTreeHash hashFunc;
        private final MTCCosignerVerifierProvider cosignerVerifierProvider;
        private final int minCosignaturesForCheckpoint;

        private final List<TrustedSubtreeEntry> trustedSubtrees = new ArrayList<TrustedSubtreeEntry>();

        /**
         * @param logId                        binary trust anchor ID of the log
         * @param hashFunc                     hash function used by the log
         * @param cosignerVerifierProvider     provider that hands back a verifier per known cosigner ID
         * @param minCosignaturesForCheckpoint minimum valid cosignatures required to trust a checkpoint
         */
        public TrustedSubtreeManager(
            byte[] logId,
            MerkleTreeHash hashFunc,
            MTCCosignerVerifierProvider cosignerVerifierProvider,
            int minCosignaturesForCheckpoint)
        {
            this.logId = logId.clone();
            this.hashFunc = hashFunc;
            this.cosignerVerifierProvider = cosignerVerifierProvider;
            this.minCosignaturesForCheckpoint = minCosignaturesForCheckpoint;
        }

        public List<TrustedSubtreeEntry> getTrustedSubtrees()
        {
            return Collections.unmodifiableList(trustedSubtrees);
        }

        /**
         * Attempts to add a new landmark subtree. The subtree is accepted if:
         * <ul>
         *   <li>The reference checkpoint carries enough valid cosignatures, and</li>
         *   <li>The supplied subtree consistency proof relates the subtree to that checkpoint.</li>
         * </ul>
         *
         * @return {@code true} if the landmark was added
         */
        public boolean addLandmarkSubtree(
            long subtreeStart,
            long subtreeEnd,
            byte[] subtreeHash,
            Checkpoint referenceCheckpoint,
            List<byte[]> consistencyProof,
            List<MTCSignature> checkpointSignatures)
            throws IOException
        {
            if (!verifyCheckpointSignatures(referenceCheckpoint, checkpointSignatures))
            {
                return false;
            }

            if (!MerkleTreePrimitives.verifySubtreeConsistencyProof(
                subtreeStart, subtreeEnd, referenceCheckpoint.treeSize,
                subtreeHash, referenceCheckpoint.rootHash,
                consistencyProof, hashFunc))
            {
                return false;
            }

            trustedSubtrees.add(new TrustedSubtreeEntry(
                subtreeStart, subtreeEnd, subtreeHash,
                referenceCheckpoint.treeSize, referenceCheckpoint.rootHash));
            return true;
        }

        private boolean verifyCheckpointSignatures(
            Checkpoint checkpoint,
            List<MTCSignature> signatures)
            throws IOException
        {
            int valid = 0;
            for (MTCSignature sig : signatures)
            {
                byte[] cosignerId = sig.getCosignerId();
                MTCCosignerVerifier verifier = cosignerVerifierProvider.get(cosignerId);
                if (verifier == null)
                {
                    continue;
                }

                // A checkpoint is a subtree with start == 0 (Section 5.4.1).
                byte[] cosignedMessage = MTCCosignedMessage.encode(
                    logId, 0L, checkpoint.treeSize, checkpoint.rootHash, cosignerId);

                OutputStream sOut = verifier.getOutputStream();
                sOut.write(cosignedMessage);
                sOut.close();
                if (verifier.verify(sig.getSignature()))
                {
                    valid++;
                }
            }
            return valid >= minCosignaturesForCheckpoint;
        }

        /**
         * A snapshot of the log: tree size and root hash.
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
}
