package org.bouncycastle.cert.plants;

import java.util.List;

import org.bouncycastle.util.Arrays;

/**
 * {@link MerkleTreeNodeSource} over an in-memory list of entry hashes, computing each
 * requested node from the entries beneath it (RFC 9162 Section 2.1.1) and keeping it.
 *
 * <p>This is what the {@code List<byte[]>} overloads of the {@link MerkleTreePrimitives}
 * generators use, and it suits the tree sizes a test, a prototype or a
 * standalone-certificate subtree handles in memory. Every full-subtree node computed is
 * cached, so the first proof over a tree of {@code n} entries costs {@code O(n)} hashes
 * and each proof after it {@code O(log^2 n)} lookups: a CA issuing a certificate for
 * every entry of a checkpoint should construct one instance and pass it to the
 * {@link MerkleTreeNodeSource} overloads, rather than call the {@code List} overloads,
 * which build a fresh instance per call and so pay the {@code O(n)} every time. The
 * cache holds one hash per internal node, about 50 bytes per entry.</p>
 *
 * <p>The list is read in place, not copied, and may grow by appending after
 * construction - the nodes of an append-only tree never change - but an entry already
 * in the list must not be replaced, as nodes above it have been kept. Instances are
 * safe to share between threads.</p>
 *
 * <p>A production log should implement {@link MerkleTreeNodeSource} over its own
 * storage instead - or extend this class and override {@link #getFullSubtreeHash} to
 * serve stored nodes, falling back to {@code super} for the rest.</p>
 */
public class ListMerkleTreeNodeSource
    implements MerkleTreeNodeSource
{
    private final List<byte[]> entryHashes;
    private final MerkleTreeHash hash;
    /**
     * {@code levels[j][i]} is {@code MTH} over the aligned full subtree
     * {@code [i << j, (i + 1) << j)}, filled on first use; level 0 is the list itself.
     */
    private final byte[][][] levels = new byte[Long.SIZE][][];

    /**
     * @param entryHashes hashes of the tree's entries, entry {@code i} at position {@code i}
     *                    (each {@code MTH({entry})}, i.e. {@link MerkleTreeHash#hashLeaf});
     *                    read in place, and may only grow by appending from now on
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
     * Returns {@code MTH(D[start:end])} computed from the entry hashes. Any range
     * covered by the list is accepted, not only full subtrees; the empty range
     * hashes to {@code HASH("")}.
     *
     * @throws IllegalArgumentException if the range is invalid or not covered by the list
     */
    public byte[] getFullSubtreeHash(long start, long end)
    {
        checkCovered(start, end);

        if (start == end)
        {
            return hash.hashRaw(new byte[0]);
        }

        return Arrays.clone(mth(start, end));
    }

    void checkCovered(long start, long end)
    {
        if (start < 0 || end < start || end > entryHashes.size())
        {
            throw new IllegalArgumentException("Interval [" + start + ", " + end
                + ") is invalid or not covered by " + entryHashes.size() + " entry hashes");
        }
    }

    /**
     * RFC 9162 Section 2.1.1 MTH over {@code [start, end)}, {@code start < end}. A full
     * subtree is answered from the cache; any other range is split at the largest power
     * of two below its size, as the definition says. The result may be a cached array,
     * so callers that hand it out clone it.
     */
    private byte[] mth(long start, long end)
    {
        long n = end - start;
        if (MerkleTreePrimitives.isFullSubtree(start, end))
        {
            return node(Long.numberOfTrailingZeros(n), start >>> Long.numberOfTrailingZeros(n));
        }

        // k: the largest power of two strictly smaller than n.
        long k = Long.highestOneBit(n - 1);

        return hash.hashNode(mth(start, start + k), mth(start + k, end));
    }

    /**
     * The hash of the full subtree {@code [index << level, (index + 1) << level)}, computed
     * from its two children and kept the first time it is asked for. The caller has
     * checked the subtree lies within the list, so {@code index} is within the level.
     */
    private synchronized byte[] node(int level, long index)
    {
        if (level == 0)
        {
            return entryHashes.get((int)index);
        }

        byte[][] row = levels[level];
        int count = entryHashes.size() >>> level;
        if (row == null || row.length < count)
        {
            // First use of this level, or the list has grown since: keep what was computed.
            byte[][] grown = new byte[count][];
            if (row != null)
            {
                System.arraycopy(row, 0, grown, 0, row.length);
            }
            levels[level] = row = grown;
        }

        byte[] value = row[(int)index];
        if (value == null)
        {
            value = hash.hashNode(node(level - 1, 2 * index), node(level - 1, 2 * index + 1));
            row[(int)index] = value;
        }
        return value;
    }
}
