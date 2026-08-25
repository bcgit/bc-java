package org.bouncycastle.cert.plants;

/**
 * Source of Merkle tree node hashes for the proof generators in
 * {@link MerkleTreePrimitives}, backed by whatever a log or CA keeps its tree in.
 *
 * <p>The generators walk the tree in the recursive form of RFC 9162 Section 2.1 and
 * the draft's Section 4.4.1, and every hash they need is either a <em>full
 * subtree</em> - a range {@code [start, end)} whose size is a power of two and
 * whose start is a multiple of that size, {@code MTH(D[start:end])} being one
 * node of the tree - or a right-hand range that
 * {@link MerkleTreePrimitives#computeMerkleTreeHash(MerkleTreeNodeSource, long, long, MerkleTreeHash)}
 * combines from at most one full subtree per level. So a production log, which
 * cannot hold its entries in memory, only has to answer for the nodes it would
 * store or cache anyway; an in-memory tree of entry hashes can be adapted with
 * {@link ListMerkleTreeNodeSource}.</p>
 *
 * <p>A proof over a tree of size {@code n} makes {@code O(log n)} requests per
 * proof element for a range that is not itself full, {@code O(log^2 n)} in all.
 * Requests are never made outside the ranges the caller passed to the generator,
 * so an implementation may treat any other request as an error.</p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9162#section-2.1">RFC 9162 Section 2.1</a>
 */
public interface MerkleTreeNodeSource
{
    /**
     * Returns the hash {@code MTH(D[start:end])} of a full subtree.
     *
     * @param start subtree start index (inclusive), a multiple of {@code end - start}
     * @param end   subtree end index (exclusive); {@code end - start} is a power of two
     * @return the node hash; for {@code end == start + 1} this is the entry hash
     *         {@code MTH({entry})}, i.e. {@link MerkleTreeHash#hashLeaf} of the entry
     * @throws IllegalArgumentException if the node is not available, for instance because
     *                                  {@code end} is beyond the tree's current size
     */
    byte[] getFullSubtreeHash(long start, long end);
}
