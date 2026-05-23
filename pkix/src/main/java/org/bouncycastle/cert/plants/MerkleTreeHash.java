package org.bouncycastle.cert.plants;

/**
 * Operator interface for the hash function used in the Merkle tree, as defined
 * by Section 4 of draft-ietf-plants-merkle-tree-certs.
 *
 * <p>JCA-free and lightweight-crypto-free: the lightweight SHA-256 binding
 * lives in {@code org.bouncycastle.cert.plants.bc.BcSha256MerkleTreeHash}.
 * A JCA-side binding is expected to live under
 * {@code org.bouncycastle.cert.plants.jcajce}.</p>
 */
public interface MerkleTreeHash
{
    /**
     * @return the hash output size in bytes
     */
    int getHashSize();

    /**
     * Hash of a leaf entry: HASH(0x00 || entry).
     *
     * @param entry the raw entry bytes
     * @return leaf hash
     */
    byte[] hashLeaf(byte[] entry);

    /**
     * Hash of an internal node: HASH(0x01 || left || right).
     *
     * @param left  left child hash
     * @param right right child hash
     * @return node hash
     */
    byte[] hashNode(byte[] left, byte[] right);

    /**
     * Raw hash with no domain separation prefix: HASH(data). Used for the
     * subjectPublicKeyInfoHash in a TBSCertificateLogEntry (Section 5.3),
     * which is computed with the log's hash function but without the
     * leaf-node prefix.
     *
     * @param data the input bytes
     * @return the hash output
     */
    byte[] hashRaw(byte[] data);
}
