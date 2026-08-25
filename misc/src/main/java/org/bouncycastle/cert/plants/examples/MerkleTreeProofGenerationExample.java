package org.bouncycastle.cert.plants.examples;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.cert.plants.MerkleTreeHash;
import org.bouncycastle.cert.plants.MerkleTreeNodeSource;
import org.bouncycastle.cert.plants.MerkleTreePrimitives;
import org.bouncycastle.cert.plants.bc.BcSha256MerkleTreeHash;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Log-side walkthrough of the Merkle tree proof generators in
 * {@link MerkleTreePrimitives} (Section 4 of draft-ietf-plants-merkle-tree-certs).
 *
 * <p>The other examples in this package build their proofs by hand from a
 * handful of {@link MerkleTreeHash#hashNode} calls, which is fine for a
 * two-entry tree but not for anything a real log or CA would keep. This
 * example runs the same steps a log takes for a tree of arbitrary size:</p>
 * <ol>
 *   <li><b>Entry hashes</b> — each log entry is hashed once with
 *       {@link MerkleTreeHash#hashLeaf} (for certificates this is
 *       {@code MerkleTreeCertificateValidator.computeEntryHash}); the
 *       generators only ever see these hashes, never the entries.</li>
 *   <li><b>Subtree hashes</b> — {@link MerkleTreePrimitives#computeMerkleTreeHash}
 *       gives {@code MTH(D[start:end])} for the tree root, a landmark subtree, or
 *       any other range (RFC 9162 Section 2.1.1).</li>
 *   <li><b>Inclusion proof</b> — {@link MerkleTreePrimitives#generateSubtreeInclusionProof}
 *       produces the sibling hashes an {@code MTCProof} carries for one entry
 *       within a subtree (Section 4.3; RFC 9162 {@code PATH}). This is the
 *       list {@code LandmarkCertificateManager.buildLandmarkCertificate} and
 *       {@code MTCContentSigner} take as input.</li>
 *   <li><b>Consistency proof</b> — {@link MerkleTreePrimitives#generateSubtreeConsistencyProof}
 *       implements {@code SUBTREE_PROOF} (Section 4.4.1), relating a landmark
 *       subtree to a later, larger checkpoint so a relying party can accept
 *       the subtree per Section 7.4 ({@code TrustedSubtreeManager}).</li>
 *   <li><b>Storage-backed trees</b> — the same generators over a
 *       {@link MerkleTreeNodeSource}, the interface a production log implements
 *       so proofs can be generated from stored node hashes without holding the
 *       entries in memory.</li>
 * </ol>
 * <p>Each proof is then checked with the verifier the relying party would
 * run, so the example doubles as a demonstration that the two directions
 * agree.</p>
 */
public class MerkleTreeProofGenerationExample
{
    public static void main(String[] args)
    {
        MerkleTreeHash hashFunc = new BcSha256MerkleTreeHash();

        // 1. A log with 13 entries. In an MTC log each entry would be a
        //    MerkleTreeCertEntry; here a short string stands in for it, and
        //    the entry hash MTH({entry}) is all the tree code ever needs.
        int treeSize = 13;
        List<byte[]> entryHashes = new ArrayList<byte[]>();
        for (int i = 0; i < treeSize; i++)
        {
            entryHashes.add(hashFunc.hashLeaf(Strings.toByteArray("log entry " + i)));
        }
        System.out.println("Tree size:                 " + treeSize);

        // 2. Subtree hashes. The root hash is what the log's checkpoint
        //    commits to; [8, 12) is a subtree in the Section 4.1 sense (its
        //    start is a multiple of its size), so it could be published as a
        //    landmark subtree.
        byte[] rootHash = MerkleTreePrimitives.computeMerkleTreeHash(entryHashes, 0, treeSize, hashFunc);
        long start = 8, end = 12;
        byte[] subtreeHash = MerkleTreePrimitives.computeMerkleTreeHash(entryHashes, start, end, hashFunc);
        System.out.println("MTH(D[0:" + treeSize + "]):              " + Hex.toHexString(rootHash));
        System.out.println("MTH(D[" + start + ":" + end + "]):              " + Hex.toHexString(subtreeHash));
        System.out.println("[" + start + ", " + end + ") is a valid subtree: "
            + MerkleTreePrimitives.isValidSubtree(start, end));

        // 3. Inclusion proof for entry 10 within the subtree [8, 12): the
        //    sibling hashes from the entry up to the subtree root. For a
        //    four-entry subtree that is two hashes.
        long index = 10;
        List<byte[]> inclusionProof = MerkleTreePrimitives.generateSubtreeInclusionProof(
            index, start, end, entryHashes, hashFunc);
        System.out.println();
        System.out.println("Inclusion proof for entry " + index + " in [" + start + ", " + end + "):");
        print(inclusionProof);

        //    The relying party recomputes the subtree hash from the entry hash
        //    and the proof and compares it with the subtree it trusts.
        boolean inclusionOk = MerkleTreePrimitives.verifySubtreeInclusionProof(
            index, start, end, entryHashes.get((int)index), subtreeHash, inclusionProof, hashFunc);
        System.out.println("Inclusion proof verifies:  " + inclusionOk);

        // 4. Consistency proof showing that the subtree [8, 12) is contained
        //    in the tree of size 13 - what a relying party needs, alongside a
        //    cosigned checkpoint for MTH(D[0:13]), before it will trust the
        //    subtree for landmark-relative certificates.
        List<byte[]> consistencyProof = MerkleTreePrimitives.generateSubtreeConsistencyProof(
            start, end, treeSize, entryHashes, hashFunc);
        System.out.println();
        System.out.println("Consistency proof for [" + start + ", " + end + ") in tree of size " + treeSize + ":");
        print(consistencyProof);

        boolean consistencyOk = MerkleTreePrimitives.verifySubtreeConsistencyProof(
            start, end, treeSize, subtreeHash, rootHash, consistencyProof, hashFunc);
        System.out.println("Consistency proof verifies: " + consistencyOk);

        // 5. The log grows. A proof generated against the old size does not
        //    verify against the new root, so the log regenerates it - the
        //    subtree hash itself is unchanged, only the path to the root is.
        entryHashes.add(hashFunc.hashLeaf(Strings.toByteArray("log entry " + treeSize)));
        entryHashes.add(hashFunc.hashLeaf(Strings.toByteArray("log entry " + (treeSize + 1))));
        int newSize = entryHashes.size();
        byte[] newRoot = MerkleTreePrimitives.computeMerkleTreeHash(entryHashes, 0, newSize, hashFunc);
        List<byte[]> newProof = MerkleTreePrimitives.generateSubtreeConsistencyProof(
            start, end, newSize, entryHashes, hashFunc);
        System.out.println();
        System.out.println("Tree grown to size " + newSize + "; old proof verifies against new root: "
            + MerkleTreePrimitives.verifySubtreeConsistencyProof(
                start, end, newSize, subtreeHash, newRoot, consistencyProof, hashFunc));
        System.out.println("Regenerated proof verifies:                                 "
            + MerkleTreePrimitives.verifySubtreeConsistencyProof(
                start, end, newSize, subtreeHash, newRoot, newProof, hashFunc));
        System.out.println("Subtree hash unchanged:                                     "
            + Arrays.areEqual(subtreeHash,
                MerkleTreePrimitives.computeMerkleTreeHash(entryHashes, start, end, hashFunc)));

        // 6. Two identities from Section 4.4.1: with start == 0 the subtree
        //    consistency proof is the RFC 9162 consistency proof PROOF(end, D_n),
        //    and with end == start + 1 it is the inclusion proof PATH(start, D_n).
        List<byte[]> asPath = MerkleTreePrimitives.generateSubtreeConsistencyProof(
            index, index + 1, newSize, entryHashes, hashFunc);
        List<byte[]> path = MerkleTreePrimitives.generateSubtreeInclusionProof(
            index, 0, newSize, entryHashes, hashFunc);
        System.out.println("SUBTREE_PROOF(" + index + ", " + (index + 1) + ", D_n) == PATH(" + index + ", D_n): "
            + sameHashes(asPath, path));

        // 7. A production log does not hold its entries in a List. It stores
        //    (or caches) the hashes of the tree's full subtrees - ranges whose
        //    size is a power of two and whose start is aligned to it - and
        //    implements MerkleTreeNodeSource over that storage; the generators
        //    request only such nodes, one per tree level per proof element.
        //    Here a HashMap stands in for the storage.
        final Map<String, byte[]> storage = new HashMap<String, byte[]>();
        for (long size = 1; size <= newSize; size <<= 1)
        {
            for (long from = 0; from + size <= newSize; from += size)
            {
                storage.put(from + ":" + (from + size),
                    MerkleTreePrimitives.computeMerkleTreeHash(entryHashes, from, from + size, hashFunc));
            }
        }
        MerkleTreeNodeSource storedTree = new MerkleTreeNodeSource()
        {
            public byte[] getFullSubtreeHash(long from, long to)
            {
                byte[] node = storage.get(from + ":" + to);
                if (node == null)
                {
                    throw new IllegalArgumentException("node [" + from + ", " + to + ") not in storage");
                }
                return node;
            }
        };
        List<byte[]> storedProof = MerkleTreePrimitives.generateSubtreeConsistencyProof(
            start, end, newSize, storedTree, hashFunc);
        System.out.println();
        System.out.println("Stored full subtrees:                                       " + storage.size());
        System.out.println("Consistency proof from storage equals in-memory proof:      "
            + sameHashes(storedProof, newProof));
        System.out.println("Inclusion proof from storage equals in-memory proof:        "
            + sameHashes(
                MerkleTreePrimitives.generateSubtreeInclusionProof(index, start, end, storedTree, hashFunc),
                MerkleTreePrimitives.generateSubtreeInclusionProof(index, start, end, entryHashes, hashFunc)));
    }

    private static void print(List<byte[]> proof)
    {
        for (int i = 0; i < proof.size(); i++)
        {
            System.out.println("  [" + i + "] " + Hex.toHexString(proof.get(i)));
        }
    }

    private static boolean sameHashes(List<byte[]> a, List<byte[]> b)
    {
        if (a.size() != b.size())
        {
            return false;
        }
        for (int i = 0; i < a.size(); i++)
        {
            if (!Arrays.areEqual(a.get(i), b.get(i)))
            {
                return false;
            }
        }
        return true;
    }
}
