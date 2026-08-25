package org.bouncycastle.cert.plants;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.util.Arrays;

/**
 * Merkle Tree primitives for Merkle Tree Certificates (PLANTS).
 * Implements the generation and verification of subtree inclusion proofs and
 * subtree consistency proofs, the Merkle Tree Hash over a range of entries, and
 * interval covering.
 *
 * <p>All algorithms are expressed against the {@link MerkleTreeHash} operator,
 * which the caller supplies; there are no direct {@code org.bouncycastle.crypto.*}
 * or {@code java.security.*} dependencies in this class.</p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/">draft-ietf-plants-merkle-tree-certs, Section 4</a>
 */
public class MerkleTreePrimitives
{
    /**
     * Evaluates a subtree inclusion proof, returning the expected subtree hash.
     *
     * @param index     absolute index of the entry in the log
     * @param start     subtree start index (inclusive)
     * @param end       subtree end index (exclusive)
     * @param entryHash hash of the entry (MTH({entry}))
     * @param proof     list of node hashes forming the inclusion proof
     * @param hash      the Merkle tree hash implementation
     * @return the expected subtree hash
     * @throws InvalidProofException if the proof is malformed or cannot be evaluated
     * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/#section-4.3.2">Section 4.3.2</a>
     */
    public static byte[] evaluateSubtreeInclusionProof(
        long index, long start, long end,
        byte[] entryHash,
        List<byte[]> proof,
        MerkleTreeHash hash)
        throws InvalidProofException
    {
        // Validate subtree interval per section 4.1, plus index range per section 4.3.2 step 1.
        if (!isValidSubtree(start, end) || index < start || index >= end)
        {
            throw new InvalidProofException("Invalid subtree interval or index");
        }

        // Convert to relative indices within the subtree
        long fn = index - start;               // relative index of the entry
        long sn = end - start - 1;              // relative index of the last entry in the subtree

        byte[] r = entryHash.clone();           // current hash

        for (byte[] p : proof)
        {
            if (sn == 0)
            {
                throw new InvalidProofException("Proof too long");
            }

            if ((fn & 1) == 1 || fn == sn)
            {
                // Hash on the left
                r = hash.hashNode(p, r);

                // Shift until the LSB of fn is set (i.e., while fn is even)
                while ((fn & 1) == 0)
                {
                    fn >>= 1;
                    sn >>= 1;
                }
            }
            else
            {
                // Hash on the right
                r = hash.hashNode(r, p);
            }

            fn >>= 1;
            sn >>= 1;
        }

        if (sn != 0)
        {
            throw new InvalidProofException("Proof too short");
        }

        return r;
    }

    /**
     * Verifies a subtree inclusion proof by comparing the evaluated hash with the given subtree hash.
     *
     * @param index       absolute index of the entry
     * @param start       subtree start
     * @param end         subtree end
     * @param entryHash   hash of the entry
     * @param subtreeHash claimed subtree hash
     * @param proof       inclusion proof
     * @param hash        hash implementation
     * @return true if the proof is valid, false otherwise
     */
    public static boolean verifySubtreeInclusionProof(
        long index, long start, long end,
        byte[] entryHash,
        byte[] subtreeHash,
        List<byte[]> proof,
        MerkleTreeHash hash)
    {
        try
        {
            byte[] computed = evaluateSubtreeInclusionProof(index, start, end, entryHash, proof, hash);
            return Arrays.areEqual(computed, subtreeHash);
        }
        catch (InvalidProofException e)
        {
            return false;
        }
    }

    /**
     * Verifies a subtree consistency proof.
     *
     * @param start       subtree start index
     * @param end         subtree end index (exclusive)
     * @param n           full tree size (number of entries)
     * @param subtreeHash hash of the subtree (MTH(D[start:end]))
     * @param rootHash    hash of the full tree (MTH(D[0:n]))
     * @param proof       list of node hashes forming the consistency proof
     * @param hash        hash implementation
     * @return true if the proof is valid, false otherwise
     * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/#section-4.4.3">Section 4.4.3</a>
     */
    public static boolean verifySubtreeConsistencyProof(
        long start, long end, long n,
        byte[] subtreeHash,
        byte[] rootHash,
        List<byte[]> proof,
        MerkleTreeHash hash)
    {
        // Validate interval per section 4.1, plus end <= n per section 4.4.3 step 1.
        if (!isValidSubtree(start, end) || end > n)
        {
            return false;
        }

        long fn = start;
        long sn = end - 1;
        long tn = n - 1;

        // ---- Step 3 & 4: skip to the starting node ----
        if (sn == tn)
        {
            // Step 3: end == n → subtree is directly contained
            while (fn != sn)
            {
                fn >>= 1;
                sn >>= 1;
                tn >>= 1;
            }
        }
        else
        {
            // Step 4: move up until fn == sn or LSB(sn) is not set
            while (fn != sn && (sn & 1) == 1)
            {
                fn >>= 1;
                sn >>= 1;
                tn >>= 1;
            }
        }

        // Initialize the two tracking hashes
        byte[] fr, sr;
        if (fn == sn)
        {
            // Starting node is the entire subtree
            fr = subtreeHash.clone();
            sr = subtreeHash.clone();
        }
        else
        {
            // Starting node is the first hash from the proof
            if (proof.isEmpty())
            {
                return false;
            }
            fr = proof.get(0).clone();
            sr = proof.get(0).clone();
            // Consume the first element (already used)
            proof = proof.subList(1, proof.size());
        }

        // ---- Step 7: incorporate the rest of the proof ----
        for (byte[] c : proof)
        {
            if (tn == 0)
            {
                return false; // proof too long
            }

            if ((sn & 1) == 1 || sn == tn)
            {
                // Incorporate on the left
                if (fn < sn)
                {
                    fr = hash.hashNode(c, fr);
                }
                sr = hash.hashNode(c, sr);

                // Section 4.4.3 step 7.2.3: "Until LSB(sn) is set, right-shift fn, sn, and tn equally."
                // The shift applies even once fn == sn (the f- and s-paths have merged);
                // sn > 0 here, so the loop terminates when sn's top bit reaches LSB.
                while ((sn & 1) == 0)
                {
                    fn >>= 1;
                    sn >>= 1;
                    tn >>= 1;
                }
            }
            else
            {
                // Incorporate on the right
                sr = hash.hashNode(sr, c);
                // No change to fr
            }

            fn >>= 1;
            sn >>= 1;
            tn >>= 1;
        }

        // ---- Step 8: final checks ----
        if (tn != 0)
        {
            return false; // proof too short
        }
        return Arrays.areEqual(fr, subtreeHash) && Arrays.areEqual(sr, rootHash);
    }

    /**
     * Computes the Merkle Tree Hash {@code MTH(D[start:end])} over a range of entries,
     * per <a href="https://www.rfc-editor.org/rfc/rfc9162#section-2.1.1">RFC 9162 Section 2.1.1</a>.
     * The range need not be a subtree in the sense of Section 4.1; any non-empty
     * {@code [start, end)} within the list is accepted, which is what the proof
     * generators need for the intermediate node hashes they emit.
     *
     * @param entryHashes hashes of the tree's entries, entry {@code i} at position {@code i}
     *                    (each {@code MTH({entry})}, i.e. {@link MerkleTreeHash#hashLeaf})
     * @param start       range start index (inclusive)
     * @param end         range end index (exclusive)
     * @param hash        the Merkle tree hash implementation
     * @return {@code MTH(D[start:end])}
     * @throws IllegalArgumentException if the range is empty or not covered by {@code entryHashes}
     */
    public static byte[] computeMerkleTreeHash(
        List<byte[]> entryHashes, long start, long end, MerkleTreeHash hash)
    {
        ListMerkleTreeNodeSource nodes = new ListMerkleTreeNodeSource(entryHashes, hash);
        nodes.checkCovered(start, end);

        return computeMerkleTreeHash(nodes, start, end, hash);
    }

    /**
     * Computes the Merkle Tree Hash {@code MTH(D[start:end])} over a range of entries
     * from a storage-backed tree, per
     * <a href="https://www.rfc-editor.org/rfc/rfc9162#section-2.1.1">RFC 9162 Section 2.1.1</a>.
     * A range that is itself a full subtree is a single request to {@code nodes}; any other
     * range is combined from at most one full subtree per level of the tree.
     *
     * @param nodes source of full-subtree hashes for the tree
     * @param start range start index (inclusive)
     * @param end   range end index (exclusive)
     * @param hash  the Merkle tree hash implementation
     * @return {@code MTH(D[start:end])}
     * @throws IllegalArgumentException if the range is empty, or {@code nodes} cannot supply a node
     */
    public static byte[] computeMerkleTreeHash(
        MerkleTreeNodeSource nodes, long start, long end, MerkleTreeHash hash)
    {
        checkRange(nodes, start, end);

        return mth(nodes, start, end, hash);
    }

    /**
     * Generates a subtree inclusion proof for the entry at {@code index} within the
     * subtree {@code [start, end)}. Per
     * <a href="https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/#section-4.3">Section 4.3</a>
     * this is the Merkle inclusion proof {@code PATH(index - start, D[start:end])} of
     * <a href="https://www.rfc-editor.org/rfc/rfc9162#section-2.1.3.1">RFC 9162 Section 2.1.3.1</a>,
     * computed over the subtree's entries. The result is accepted by
     * {@link #evaluateSubtreeInclusionProof} and {@link #verifySubtreeInclusionProof}
     * for the same {@code index}, {@code start} and {@code end}.
     *
     * @param index       absolute index of the entry in the log
     * @param start       subtree start index (inclusive)
     * @param end         subtree end index (exclusive)
     * @param entryHashes hashes of the tree's entries, entry {@code i} at position {@code i};
     *                    only positions {@code [start, end)} are read
     * @param hash        the Merkle tree hash implementation
     * @return the sibling hashes from the entry up to the subtree root (empty for a size-one subtree)
     * @throws IllegalArgumentException if {@code [start, end)} is not a valid subtree (Section 4.1),
     *                                  {@code index} lies outside it, or {@code entryHashes} does not cover it
     */
    public static List<byte[]> generateSubtreeInclusionProof(
        long index, long start, long end, List<byte[]> entryHashes, MerkleTreeHash hash)
    {
        if (!isValidSubtree(start, end) || index < start || index >= end)
        {
            throw new IllegalArgumentException("Invalid subtree interval or index");
        }
        ListMerkleTreeNodeSource nodes = new ListMerkleTreeNodeSource(entryHashes, hash);
        nodes.checkCovered(start, end);

        return generateSubtreeInclusionProof(index, start, end, nodes, hash);
    }

    /**
     * Generates a subtree inclusion proof for the entry at {@code index} within the
     * subtree {@code [start, end)} of a storage-backed tree; see
     * {@link #generateSubtreeInclusionProof(long, long, long, List, MerkleTreeHash)}.
     *
     * @param index absolute index of the entry in the log
     * @param start subtree start index (inclusive)
     * @param end   subtree end index (exclusive)
     * @param nodes source of full-subtree hashes for the tree; only nodes within
     *              {@code [start, end)} are requested
     * @param hash  the Merkle tree hash implementation
     * @return the sibling hashes from the entry up to the subtree root (empty for a size-one subtree)
     * @throws IllegalArgumentException if {@code [start, end)} is not a valid subtree (Section 4.1),
     *                                  {@code index} lies outside it, or {@code nodes} cannot supply a node
     */
    public static List<byte[]> generateSubtreeInclusionProof(
        long index, long start, long end, MerkleTreeNodeSource nodes, MerkleTreeHash hash)
    {
        if (!isValidSubtree(start, end) || index < start || index >= end)
        {
            throw new IllegalArgumentException("Invalid subtree interval or index");
        }
        checkRange(nodes, start, end);

        List<byte[]> proof = new ArrayList<byte[]>();
        path(index - start, nodes, start, end, hash, proof);
        return proof;
    }

    /**
     * Generates a subtree consistency proof {@code SUBTREE_PROOF(start, end, D_n)} showing
     * that the subtree {@code [start, end)} is contained in the tree of size {@code n}, per
     * <a href="https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/#section-4.4.1">Section 4.4.1</a>.
     * The result is accepted by {@link #verifySubtreeConsistencyProof} for the same
     * {@code start}, {@code end} and {@code n}. As the draft notes, with {@code start == 0}
     * this is the RFC 9162 consistency proof {@code PROOF(end, D_n)}, and with
     * {@code end == start + 1} it is the inclusion proof {@code PATH(start, D_n)}.
     *
     * @param start       subtree start index (inclusive)
     * @param end         subtree end index (exclusive)
     * @param n           full tree size (number of entries)
     * @param entryHashes hashes of the tree's entries, entry {@code i} at position {@code i};
     *                    positions {@code [0, n)} are read
     * @param hash        the Merkle tree hash implementation
     * @return the node hashes forming the consistency proof (empty when the subtree is the whole tree)
     * @throws IllegalArgumentException if {@code [start, end)} is not a valid subtree (Section 4.1),
     *                                  {@code end > n}, or {@code entryHashes} does not cover {@code [0, n)}
     */
    public static List<byte[]> generateSubtreeConsistencyProof(
        long start, long end, long n, List<byte[]> entryHashes, MerkleTreeHash hash)
    {
        if (!isValidSubtree(start, end) || end > n)
        {
            throw new IllegalArgumentException("Invalid subtree interval or tree size");
        }
        ListMerkleTreeNodeSource nodes = new ListMerkleTreeNodeSource(entryHashes, hash);
        nodes.checkCovered(0, n);

        return generateSubtreeConsistencyProof(start, end, n, nodes, hash);
    }

    /**
     * Generates a subtree consistency proof {@code SUBTREE_PROOF(start, end, D_n)} for the
     * subtree {@code [start, end)} in a storage-backed tree of size {@code n}; see
     * {@link #generateSubtreeConsistencyProof(long, long, long, List, MerkleTreeHash)}.
     *
     * @param start subtree start index (inclusive)
     * @param end   subtree end index (exclusive)
     * @param n     full tree size (number of entries)
     * @param nodes source of full-subtree hashes for the tree; only nodes within
     *              {@code [0, n)} are requested
     * @param hash  the Merkle tree hash implementation
     * @return the node hashes forming the consistency proof (empty when the subtree is the whole tree)
     * @throws IllegalArgumentException if {@code [start, end)} is not a valid subtree (Section 4.1),
     *                                  {@code end > n}, or {@code nodes} cannot supply a node
     */
    public static List<byte[]> generateSubtreeConsistencyProof(
        long start, long end, long n, MerkleTreeNodeSource nodes, MerkleTreeHash hash)
    {
        if (!isValidSubtree(start, end) || end > n)
        {
            throw new IllegalArgumentException("Invalid subtree interval or tree size");
        }
        checkRange(nodes, 0, n);

        List<byte[]> proof = new ArrayList<byte[]>();
        subtreeSubProof(start, end, nodes, 0, n, true, hash, proof);
        return proof;
    }

    /**
     * Whether {@code [start, end)} is a full subtree: its size is a power of two and
     * {@code start} is a multiple of that size, so {@code MTH(D[start:end])} is a single
     * node of the tree.
     *
     * @param start subtree start (inclusive)
     * @param end   subtree end (exclusive)
     * @return true if the range is one node of the tree
     */
    public static boolean isFullSubtree(long start, long end)
    {
        long size = end - start;

        return start >= 0 && size > 0 && (size & (size - 1)) == 0 && (start & (size - 1)) == 0;
    }

    private static void checkRange(MerkleTreeNodeSource nodes, long start, long end)
    {
        if (nodes == null)
        {
            throw new IllegalArgumentException("nodes must not be null");
        }
        if (start < 0 || end <= start)
        {
            throw new IllegalArgumentException("Interval [" + start + ", " + end + ") is empty");
        }
    }

    /**
     * The largest power of two strictly smaller than {@code n}, for {@code n > 1}
     * (the {@code k} of RFC 9162 Section 2.1.1).
     */
    private static long largestPowerOfTwoBelow(long n)
    {
        return Long.highestOneBit(n - 1);
    }

    /**
     * RFC 9162 Section 2.1.1 MTH over D[start:end], start &lt; end, from a node source.
     * A full subtree is one request; otherwise the left child D[start:start+k] is always
     * full (k divides start whenever the range came from the tree recursion, and the
     * split is repeated on the right child until it is), so each level costs one request.
     */
    private static byte[] mth(MerkleTreeNodeSource nodes, long start, long end, MerkleTreeHash hash)
    {
        if (isFullSubtree(start, end))
        {
            byte[] node = nodes.getFullSubtreeHash(start, end);
            if (node == null)
            {
                throw new IllegalArgumentException("Node source returned no hash for [" + start + ", " + end + ")");
            }
            return node;
        }

        long k = largestPowerOfTwoBelow(end - start);

        return hash.hashNode(mth(nodes, start, start + k, hash), mth(nodes, start + k, end, hash));
    }

    /**
     * RFC 9162 Section 2.1.3.1 PATH(m, D[start:end]), appending the sibling hashes to
     * {@code proof} leaf-side first: PATH(m, D_n) = PATH(m, D[0:k]) : MTH(D[k:n]) for
     * m &lt; k, and PATH(m - k, D[k:n]) : MTH(D[0:k]) otherwise.
     */
    private static void path(long m, MerkleTreeNodeSource d, long start, long end, MerkleTreeHash hash, List<byte[]> proof)
    {
        long n = end - start;
        if (n == 1)
        {
            return;
        }

        long k = largestPowerOfTwoBelow(n);

        if (m < k)
        {
            path(m, d, start, start + k, hash, proof);
            proof.add(mth(d, start + k, end, hash));
        }
        else
        {
            path(m - k, d, start + k, end, hash, proof);
            proof.add(mth(d, start, start + k, hash));
        }
    }

    /**
     * Section 4.4.1 SUBTREE_SUBPROOF(start, end, D[from:to], known), with {@code start}
     * and {@code end} relative to the tree slice {@code [from, to)} and {@code known}
     * tracking whether the verifier already holds the slice's hash.
     */
    private static void subtreeSubProof(
        long start, long end, MerkleTreeNodeSource d, long from, long to, boolean known,
        MerkleTreeHash hash, List<byte[]> proof)
    {
        long n = to - from;

        // SUBTREE_SUBPROOF(0, n, D_n, true) = {}; SUBTREE_SUBPROOF(0, n, D_n, false) = {MTH(D_n)}
        if (start == 0 && end == n)
        {
            if (!known)
            {
                proof.add(mth(d, from, to, hash));
            }
            return;
        }

        // Otherwise n > 1 (a valid subtree strictly inside [0, n) leaves at least two entries).
        long k = largestPowerOfTwoBelow(n);

        if (end <= k)
        {
            // Subtree on the left of k: recurse into D[0:k], include MTH(D[k:n]).
            subtreeSubProof(start, end, d, from, from + k, known, hash, proof);
            proof.add(mth(d, from + k, to, hash));
        }
        else if (k <= start)
        {
            // Subtree on the right of k: recurse into D[k:n], include MTH(D[0:k]).
            subtreeSubProof(start - k, end - k, d, from + k, to, known, hash, proof);
            proof.add(mth(d, from, from + k, hash));
        }
        else
        {
            // start < k < end, which implies start == 0: recurse into D[k:n] with the
            // subtree hash no longer known to the verifier, include MTH(D[0:k]).
            subtreeSubProof(0, end - k, d, from + k, to, false, hash, proof);
            proof.add(mth(d, from, from + k, hash));
        }
    }

    /**
     * Checks whether {@code [start, end)} is a valid subtree interval per
     * <a href="https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/#section-4.1">Section 4.1</a>:
     * 0 &lt;= start &lt; end, and start is a multiple of BIT_CEIL(end - start).
     *
     * @param start subtree start (inclusive)
     * @param end   subtree end (exclusive)
     * @return true if the interval describes a valid subtree
     */
    public static boolean isValidSubtree(long start, long end)
    {
        if (start < 0 || end <= start)
        {
            return false;
        }
        if (start == 0)
        {
            return true;
        }
        long size = end - start;
        // BIT_CEIL(size): smallest power of two greater than or equal to size.
        long bitCeil = Long.highestOneBit(size);
        if (bitCeil < size)
        {
            bitCeil <<= 1;
        }
        return bitCeil > 0 && (start & (bitCeil - 1)) == 0;
    }

    /**
     * Finds the minimal set of subtrees that efficiently cover the interval [start, end).
     * Returns a list of one or two (start, end) pairs.
     *
     * @param start start index of the interval (inclusive)
     * @param end   end index of the interval (exclusive)
     * @return list of one or two subtrees covering the interval (as long arrays of length 2)
     *
     * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/#section-4.5">Section 4.5</a>
     */
    public static List<long[]> findCoveringSubtrees(long start, long end)
    {
        if (start >= end)
        {
            throw new IllegalArgumentException("Invalid interval: start must be less than end");
        }

        List<long[]> result = new ArrayList<long[]>();

        if (end - start == 1)
        {
            result.add(new long[]{start, end});
            return result;
        }

        long last = end - 1;
        // Find where start and last's tree paths diverge
        long diff = start ^ last;
        int split = Long.SIZE - Long.numberOfLeadingZeros(diff) - 1; // highest set bit index
        long mask = (1L << split) - 1;
        long mid = last & ~mask;

        // Compute leftSplit: the number of low bits of start that are zero
        // This is the bit length of (~start) & mask
        long temp = (~start) & mask;
        int leftSplit;
        if (temp == 0)
        {
            leftSplit = 0;
        }
        else
        {
            leftSplit = Long.SIZE - Long.numberOfLeadingZeros(temp);
        }

        long leftStart = start & -(1L << leftSplit);

        result.add(new long[]{leftStart, mid});
        result.add(new long[]{mid, end});
        return result;
    }

    /**
     * Simple container for a subtree interval (start inclusive, end exclusive).
     */
    public static class SubtreeInfo
    {
        private final long start;
        private final long end;

        public SubtreeInfo(long start, long end)
        {
            this.start = start;
            this.end = end;
        }

        public long getStart()
        {
            return start;
        }

        public long getEnd()
        {
            return end;
        }

        public boolean equals(Object o)
        {
            if (this == o)
            {
                return true;
            }
            if (!(o instanceof SubtreeInfo))
            {
                return false;
            }
            SubtreeInfo other = (SubtreeInfo)o;
            return start == other.start && end == other.end;
        }

        public int hashCode()
        {
            int h = (int)(start ^ (start >>> 32));
            h = 31 * h + (int)(end ^ (end >>> 32));
            return h;
        }

        public String toString()
        {
            return "[" + start + ", " + end + ")";
        }
    }
}
