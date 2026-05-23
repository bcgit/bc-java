package org.bouncycastle.cert.plants;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.util.Arrays;

/**
 * Merkle Tree primitives for Merkle Tree Certificates (PLANTS).
 * Implements subtree inclusion proofs, consistency proofs, and interval covering.
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
                // I.e. continue shifting while LSB(sn) is unset.
                while ((sn & 1) == 0 && fn < sn)
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
    }
}
