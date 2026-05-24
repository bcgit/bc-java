package org.bouncycastle.cert.plants;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Operator interface for the hash function used in the Merkle tree, as defined
 * by Section 4 of draft-ietf-plants-merkle-tree-certs.
 *
 * <p>JCA-free and lightweight-crypto-free. Concrete SHA-256 bindings:
 * {@code org.bouncycastle.cert.plants.bc.BcSha256MerkleTreeHash} (lightweight)
 * and {@code org.bouncycastle.cert.plants.jcajce.JcaSha256MerkleTreeHash} (JCA).</p>
 */
public interface MerkleTreeHash
{
    /**
     * @return the X.509 {@code AlgorithmIdentifier} that names this hash
     *         function. Used by {@link MerkleTreeCertificateValidator} to
     *         cross-check the supplied hash against the {@code logHash} field
     *         of the CA's {@code id-pe-mtcCertificationAuthority} extension.
     */
    AlgorithmIdentifier getAlgorithmIdentifier();

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
