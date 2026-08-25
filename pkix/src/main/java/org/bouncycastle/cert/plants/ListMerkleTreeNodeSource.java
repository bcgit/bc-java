package org.bouncycastle.cert.plants;

import java.util.List;

import org.bouncycastle.util.Arrays;

/**
 * {@link MerkleTreeNodeSource} over an in-memory list of entry hashes, computing each
 * requested node from the entries beneath it (RFC 9162 Section 2.1.1).
 *
 * <p>This is what the {@code List<byte[]>} overloads of the {@link MerkleTreePrimitives}
 * generators use, and it suits the tree sizes a test, a prototype or a
 * standalone-certificate subtree handles in memory. A production log should implement
 * {@link MerkleTreeNodeSource} over its own storage instead - or extend this class and
 * override {@link #getFullSubtreeHash} to serve cached nodes, falling back to
 * {@code super} for the rest.</p>
 */
public class ListMerkleTreeNodeSource
    implements MerkleTreeNodeSource
{
    private final List<byte[]> entryHashes;
    private final MerkleTreeHash hash;

    /**
     * @param entryHashes hashes of the tree's entries, entry {@code i} at position {@code i}
     *                    (each {@code MTH({entry})}, i.e. {@link MerkleTreeHash#hashLeaf})
     * @param hash        the Merkle tree hash implementation
     */
    public ListMerkleTreeNodeSource(List<byte[]> entryHashes, MerkleTreeHash hash)
    {
        if (entryHashes == null)
        {
            throw new IllegalArgumentException("entryHashes must not be null");
        }
        if (hash == null)
        {
            throw new IllegalArgumentException("hash must not be null");
        }
        this.entryHashes = entryHashes;
        this.hash = hash;
    }

    /**
     * @return the number of entries in the tree
     */
    public long size()
    {
        return entryHashes.size();
    }

    /**
     * Returns {@code MTH(D[start:end])} computed from the entry hashes. Any non-empty
     * range covered by the list is accepted, not only full subtrees.
     *
     * @throws IllegalArgumentException if the range is empty or not covered by the list
     */
    public byte[] getFullSubtreeHash(long start, long end)
    {
        checkCovered(start, end);

        return mth(start, end);
    }

    void checkCovered(long start, long end)
    {
        if (start < 0 || end <= start || end > entryHashes.size())
        {
            throw new IllegalArgumentException("Interval [" + start + ", " + end
                + ") is empty or not covered by " + entryHashes.size() + " entry hashes");
        }
    }

    private byte[] mth(long start, long end)
    {
        long n = end - start;
        if (n == 1)
        {
            return Arrays.clone(entryHashes.get((int)start));
        }

        // k: the largest power of two strictly smaller than n.
        long k = Long.highestOneBit(n - 1);

        return hash.hashNode(mth(start, start + k), mth(start + k, end));
    }
}
