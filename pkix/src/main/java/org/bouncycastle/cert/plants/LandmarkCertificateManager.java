package org.bouncycastle.cert.plants;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.plants.CloudFlareObjectIdentifiers;
import org.bouncycastle.asn1.plants.MTCSignature;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.TBSCertificateLogEntry;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.plants.MTCSignatureVerifier;
import org.bouncycastle.crypto.plants.MerkleTreePrimitives;
import org.bouncycastle.util.Arrays;

/**
 * Helpers for constructing landmark-relative certificates and for maintaining a
 * relying party's trusted-subtree list, as described in Sections 6.3 and 7.4 of
 * draft-ietf-plants-merkle-tree-certs.
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
        MerkleTreePrimitives.MerkleTreeHash hashFunc)
        throws IOException
    {
        TBSCertificate tbs = buildTBSCertificate(tbsCertEntry, index, subjectPublicKeyInfo);

        byte[] inclusionProofBytes = concatenateHashes(inclusionProof, hashFunc.getHashSize());
        MTCProof proof = new MTCProof(
            landmarkSubtree.getStart(),
            landmarkSubtree.getEnd(),
            inclusionProofBytes,
            Collections.<MTCSignature>emptyList());

        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(CloudFlareObjectIdentifiers.id_alg_mtcProof);
        DERBitString signature = new DERBitString(proof.encode());

        return new X509CertificateHolder(
            new DERSequence(new ASN1Encodable[]{tbs.toASN1Primitive(), sigAlg, signature}).getEncoded());
    }

    private static TBSCertificate buildTBSCertificate(
        TBSCertificateLogEntry tbsEntry,
        long index,
        SubjectPublicKeyInfo subjectPublicKeyInfo)
    {
        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(CloudFlareObjectIdentifiers.id_alg_mtcProof);

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

    // ------------------------------------------------------------------------
    // Trusted subtree management (Section 7.4)
    // ------------------------------------------------------------------------

    /**
     * A trusted subtree along with the reference checkpoint that proved its consistency.
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
        private final MerkleTreePrimitives.MerkleTreeHash hashFunc;
        private final Map<MerkleTreeCertificateValidator.ByteArrayKey, AsymmetricKeyParameter> cosignerPublicKeys;
        private final int minCosignaturesForCheckpoint;

        private final List<TrustedSubtreeEntry> trustedSubtrees = new ArrayList<TrustedSubtreeEntry>();

        /**
         * @param logId                        binary trust anchor ID of the log
         * @param hashFunc                     hash function used by the log
         * @param cosignerPublicKeys           map from binary cosigner ID to public key
         * @param minCosignaturesForCheckpoint minimum valid cosignatures required to trust a checkpoint
         */
        public TrustedSubtreeManager(
            byte[] logId,
            MerkleTreePrimitives.MerkleTreeHash hashFunc,
            Map<MerkleTreeCertificateValidator.ByteArrayKey, AsymmetricKeyParameter> cosignerPublicKeys,
            int minCosignaturesForCheckpoint)
        {
            this.logId = logId.clone();
            this.hashFunc = hashFunc;
            this.cosignerPublicKeys = cosignerPublicKeys;
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
                AsymmetricKeyParameter pubKey = cosignerPublicKeys.get(
                    new MerkleTreeCertificateValidator.ByteArrayKey(cosignerId));
                if (pubKey == null)
                {
                    continue;
                }

                String algorithm = getAlgorithmFromKey(pubKey);
                if (algorithm == null)
                {
                    continue;
                }

                // A checkpoint is a subtree with start == 0 (Section 5.4.1).
                boolean ok = MTCSignatureVerifier.verify(
                    logId,
                    0L,
                    checkpoint.treeSize,
                    checkpoint.rootHash,
                    cosignerId,
                    sig.getSignature(),
                    pubKey,
                    algorithm);
                if (ok)
                {
                    valid++;
                }
            }
            return valid >= minCosignaturesForCheckpoint;
        }

        private static String getAlgorithmFromKey(AsymmetricKeyParameter key)
        {
            if (key instanceof ECPublicKeyParameters)
            {
                ECPublicKeyParameters ec = (ECPublicKeyParameters)key;
                int fieldSize = ec.getParameters().getCurve().getFieldSize();
                if (fieldSize == 256)
                {
                    return "ECDSA-P256-SHA256";
                }
                if (fieldSize == 384)
                {
                    return "ECDSA-P384-SHA384";
                }
                return null;
            }
            if (key instanceof Ed25519PublicKeyParameters)
            {
                return "Ed25519";
            }
            if (key.getClass().getName().contains("MLDSAPublicKeyParameters"))
            {
                return "ML-DSA-65";
            }
            return null;
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
