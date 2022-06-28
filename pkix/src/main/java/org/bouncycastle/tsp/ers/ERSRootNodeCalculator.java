package org.bouncycastle.tsp.ers;

import org.bouncycastle.asn1.tsp.PartialHashtree;
import org.bouncycastle.operator.DigestCalculator;

/**
 * Base interface for an implementation that calculates the root hash
 * contained in the time-stamp from the Merkle tree based on the partial
 * hash-tree nodes.
 */
public interface ERSRootNodeCalculator
{
    /**
     * Calculate the root hash of the Merkle tree from the partial hash-tree nodes.
     *
     * @param digCalc the digest calculator to use.
     * @param nodes the partial hash-trees forming the basis of the Merkle tree.
     * @return the root hash of the Merkle tree.
     */
    byte[] computeRootHash(DigestCalculator digCalc, PartialHashtree[] nodes);

    /**
     * Calculate a path from the leaf node to the root of the last computed Merkle tree.
     * 
     * @param digCalc the digest calculator to use.
     * @param node the leaf node at the start of the path.
     * @param index the index of the node in the original list of partial hash trees.
     * @return
     */
    PartialHashtree[] computePathToRoot(DigestCalculator digCalc, PartialHashtree node, int index);

    /**
     * Recover the root hash from a path made up of PartialHashtrees.
     *
     * @param digCalc the digest calculator to use.
     * @param nodes the partial hash-trees forming a path from a leaf to the root of the Merkle tree.
     * @return the root hash of the Merkle tree.
     */
    byte[] recoverRootHash(DigestCalculator digCalc, PartialHashtree[] nodes);
}
