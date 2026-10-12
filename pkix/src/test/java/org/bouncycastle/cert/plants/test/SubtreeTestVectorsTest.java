package org.bouncycastle.cert.plants.test;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.cert.plants.MerkleTreeHash;
import org.bouncycastle.cert.plants.MerkleTreePrimitives;
import org.bouncycastle.cert.plants.bc.BcSha256MerkleTreeHash;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

/**
 * The subtree test vectors of Appendix C of draft-ietf-plants-merkle-tree-certs-07.
 *
 * <p>Appendix C.1: for trees of every size up to 130, with leaf {@code d[i]} the
 * single byte {@code i}, each output of the Section 4 algorithms is rendered as a
 * text line and folded into one running SHA-256; the draft fixes the four
 * resulting digests.</p>
 *
 * <p>Appendix C.2.2 and C.2.3: the large-tree inclusion and consistency proofs
 * the draft publishes alongside, for trees of size about 2^48, 2^63 and 2^64,
 * applied to the relying-party side (Section 4.3.2 evaluation and Section 4.4.3
 * verification) together with the negative variants Appendix C.1 prescribes.
 * The files are read from {@code pkix/plants} in bc-test-data.</p>
 */
public class SubtreeTestVectorsTest
    extends SimpleTest
{
    private static final int MAX_SIZE = 130;

    /** Cases in large_inclusion_proofs.json whose tree fits a signed 64-bit integer. */
    private static final int LARGE_INCLUSION_CASES = 16;
    /** Cases in large_consistency_proofs.json whose tree fits a signed 64-bit integer. */
    private static final int LARGE_CONSISTENCY_CASES = 14;

    private static final String SUBTREE_HASHES = "b82806ad4265bb151c1119c0f4db437bb4d1a1f887b3a7fba1cd4ebf552e3e81";
    private static final String INCLUSION_PROOFS = "ac2a8f989e44d99e399db448050ff5f19757df53cfb716aa81015d3955d8163f";
    private static final String CONSISTENCY_PROOFS = "10fa99b37bf9bf9ffa26b412fbd98bd75363256d0b75d61bc4538b9c9c5a0a74";
    private static final String COVERING_SUBTREES = "7fd9c8b926e9d2b5cf831560e8ce295a5ef97ad5c5ede4ea0dea28a8c8fc8bb0";

    public String getName()
    {
        return "SubtreeTestVectors";
    }

    public void performTest()
        throws Exception
    {
        MerkleTreeHash hash = new BcSha256MerkleTreeHash();
        List<byte[]> entries = new ArrayList<byte[]>(MAX_SIZE);
        for (int i = 0; i < MAX_SIZE; i++)
        {
            entries.add(hash.hashLeaf(new byte[]{ (byte)i }));
        }

        subtreeHashes(entries, hash);
        inclusionProofs(entries, hash);
        consistencyProofs(entries, hash);
        coveringSubtrees();
        largeInclusionProofs(hash);
        largeConsistencyProofs(hash);
    }

    // C.2.2: evaluate each published proof (Section 4.3.2) and check that a proof one hash
    // short, one hash long, or evaluated for the wrong entry hash fails. Trees above 2^63 - 1
    // cannot be expressed as a long and are skipped, as Appendix C.2 permits above 2^48 - 1.
    private void largeInclusionProofs(MerkleTreeHash hash)
        throws IOException
    {
        byte[] junk = hash.hashLeaf(Strings.toByteArray("not a proof node"));
        int checked = 0;
        for (Map<String, String> v : readVectors("large_inclusion_proofs.json"))
        {
            long index = asLong(v.get("Index"));
            long start = asLong(v.get("Start"));
            long end = asLong(v.get("End"));
            if (index < 0 || start < 0 || end < 0)
            {
                continue;
            }
            String name = "C.2.2 entry " + index + " of [" + start + ", " + end + ")";
            byte[] entryHash = Base64.decode(v.get("EntryHash"));
            byte[] subtreeHash = Base64.decode(v.get("SubtreeHash"));
            List<byte[]> proof = split(Base64.decode(v.get("Proof")), hash.getHashSize());

            isTrue(name + " verifies", MerkleTreePrimitives.verifySubtreeInclusionProof(
                index, start, end, entryHash, subtreeHash, proof, hash));
            isTrue(name + " rejects an extended proof", !MerkleTreePrimitives.verifySubtreeInclusionProof(
                index, start, end, entryHash, subtreeHash, append(proof, junk), hash));
            if (!proof.isEmpty())
            {
                isTrue(name + " rejects a truncated proof", !MerkleTreePrimitives.verifySubtreeInclusionProof(
                    index, start, end, entryHash, subtreeHash, proof.subList(0, proof.size() - 1), hash));
            }
            isTrue(name + " rejects another entry hash", !MerkleTreePrimitives.verifySubtreeInclusionProof(
                index, start, end, junk, subtreeHash, proof, hash));
            checked++;
        }
        isTrue("C.2.2 vectors read: " + checked, checked == LARGE_INCLUSION_CASES);
    }

    // C.2.3: check each published proof (Section 4.4.3) and, per Appendix C.1.3 steps 3 to 6,
    // that a proof one hash short or one hash long, a flipped subtree hash, and (for a non-empty
    // subtree) a flipped tree hash all fail. Trees above 2^63 - 1 are skipped as above.
    private void largeConsistencyProofs(MerkleTreeHash hash)
        throws IOException
    {
        byte[] junk = hash.hashLeaf(Strings.toByteArray("not a proof node"));
        int checked = 0;
        for (Map<String, String> v : readVectors("large_consistency_proofs.json"))
        {
            long start = asLong(v.get("Start"));
            long end = asLong(v.get("End"));
            long n = asLong(v.get("TreeSize"));
            if (start < 0 || end < 0 || n < 0)
            {
                continue;
            }
            String name = "C.2.3 subtree [" + start + ", " + end + ") of " + n;
            byte[] subtreeHash = Base64.decode(v.get("SubtreeHash"));
            byte[] treeHash = Base64.decode(v.get("TreeHash"));
            List<byte[]> proof = split(Base64.decode(v.get("Proof")), hash.getHashSize());

            isTrue(name + " verifies", MerkleTreePrimitives.verifySubtreeConsistencyProof(
                start, end, n, subtreeHash, treeHash, proof, hash));
            isTrue(name + " rejects an extended proof", !MerkleTreePrimitives.verifySubtreeConsistencyProof(
                start, end, n, subtreeHash, treeHash, append(proof, junk), hash));
            if (!proof.isEmpty())
            {
                isTrue(name + " rejects a truncated proof", !MerkleTreePrimitives.verifySubtreeConsistencyProof(
                    start, end, n, subtreeHash, treeHash, proof.subList(0, proof.size() - 1), hash));
            }
            isTrue(name + " rejects a flipped subtree hash", !MerkleTreePrimitives.verifySubtreeConsistencyProof(
                start, end, n, flipBit(subtreeHash), treeHash, proof, hash));
            if (start != end)
            {
                isTrue(name + " rejects a flipped tree hash", !MerkleTreePrimitives.verifySubtreeConsistencyProof(
                    start, end, n, subtreeHash, flipBit(treeHash), proof, hash));
            }
            checked++;
        }
        isTrue("C.2.3 vectors read: " + checked, checked == LARGE_CONSISTENCY_CASES);
    }

    /**
     * Reads one of the vector files: a JSON list of flat objects whose values are all
     * strings, which is all the scanner below understands.
     */
    private static List<Map<String, String>> readVectors(String fileName)
        throws IOException
    {
        String text = Strings.fromByteArray(Streams.readAll(TestResourceFinder.findTestResource("pkix/plants", fileName)));
        Pattern field = Pattern.compile("\"([A-Za-z]+)\"\\s*:\\s*\"([^\"]*)\"");
        List<Map<String, String>> vectors = new ArrayList<Map<String, String>>();
        Matcher object = Pattern.compile("\\{([^}]*)\\}").matcher(text);
        while (object.find())
        {
            Map<String, String> values = new HashMap<String, String>();
            Matcher f = field.matcher(object.group(1));
            while (f.find())
            {
                values.put(f.group(1), f.group(2));
            }
            vectors.add(values);
        }
        return vectors;
    }

    /** The decimal value, or -1 when it does not fit a signed long. */
    private static long asLong(String decimal)
    {
        BigInteger value = new BigInteger(decimal);
        return value.bitLength() > 63 ? -1 : value.longValue();
    }

    private static List<byte[]> split(byte[] concatenated, int hashSize)
    {
        List<byte[]> hashes = new ArrayList<byte[]>();
        for (int off = 0; off < concatenated.length; off += hashSize)
        {
            hashes.add(Arrays.copyOfRange(concatenated, off, off + hashSize));
        }
        return hashes;
    }

    private static List<byte[]> append(List<byte[]> proof, byte[] extra)
    {
        List<byte[]> longer = new ArrayList<byte[]>(proof);
        longer.add(extra);
        return longer;
    }

    private static byte[] flipBit(byte[] hash)
    {
        byte[] flipped = Arrays.clone(hash);
        flipped[0] ^= 0x01;
        return flipped;
    }

    // C.1.1: "[START, END) HASH\n" for every valid subtree, the empty ones included.
    private void subtreeHashes(List<byte[]> entries, MerkleTreeHash hash)
    {
        Digest acc = new SHA256Digest();
        for (int end = 0; end <= MAX_SIZE; end++)
        {
            for (int start = 0; start <= end; start++)
            {
                if (MerkleTreePrimitives.isValidSubtree(start, end))
                {
                    byte[] mth = MerkleTreePrimitives.computeMerkleTreeHash(entries, start, end, hash);
                    update(acc, interval(start, end) + " " + Hex.toHexString(mth) + "\n");
                }
            }
        }
        check("C.1.1 subtree hashes", acc, SUBTREE_HASHES);
    }

    // C.1.2: "INDEX [START, END)" + " HASH" per proof node + "\n" for every entry of every valid subtree.
    private void inclusionProofs(List<byte[]> entries, MerkleTreeHash hash)
    {
        Digest acc = new SHA256Digest();
        for (int end = 0; end <= MAX_SIZE; end++)
        {
            for (int start = 0; start <= end; start++)
            {
                if (!MerkleTreePrimitives.isValidSubtree(start, end))
                {
                    continue;
                }
                for (int index = start; index < end; index++)
                {
                    List<byte[]> proof = MerkleTreePrimitives.generateSubtreeInclusionProof(
                        index, start, end, entries, hash);
                    update(acc, index + " " + interval(start, end) + hashes(proof) + "\n");
                }
            }
        }
        check("C.1.2 subtree inclusion proofs", acc, INCLUSION_PROOFS);
    }

    // C.1.3: "[START, END) N" + " HASH" per proof node + "\n" for every valid subtree of every tree size n.
    private void consistencyProofs(List<byte[]> entries, MerkleTreeHash hash)
    {
        Digest acc = new SHA256Digest();
        for (int n = 0; n <= MAX_SIZE; n++)
        {
            for (int end = 0; end <= n; end++)
            {
                for (int start = 0; start <= end; start++)
                {
                    if (!MerkleTreePrimitives.isValidSubtree(start, end))
                    {
                        continue;
                    }
                    List<byte[]> proof = MerkleTreePrimitives.generateSubtreeConsistencyProof(
                        start, end, n, entries, hash);
                    update(acc, interval(start, end) + " " + n + hashes(proof) + "\n");
                }
            }
        }
        check("C.1.3 subtree consistency proofs", acc, CONSISTENCY_PROOFS);
    }

    // C.1.4: the two covering subtrees "[LS, LE) [RS, RE)\n" for every interval, empty ones included.
    private void coveringSubtrees()
    {
        Digest acc = new SHA256Digest();
        for (int end = 0; end <= MAX_SIZE; end++)
        {
            for (int start = 0; start <= end; start++)
            {
                List<long[]> covering = MerkleTreePrimitives.findCoveringSubtrees(start, end);
                isTrue("two covering subtrees for " + interval(start, end), covering.size() == 2);
                long[] left = (long[])covering.get(0);
                long[] right = (long[])covering.get(1);
                update(acc, interval(left[0], left[1]) + " " + interval(right[0], right[1]) + "\n");
            }
        }
        check("C.1.4 efficient covering subtrees", acc, COVERING_SUBTREES);
    }

    private static String interval(long start, long end)
    {
        return "[" + start + ", " + end + ")";
    }

    private static String hashes(List<byte[]> proof)
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < proof.size(); i++)
        {
            sb.append(' ').append(Hex.toHexString((byte[])proof.get(i)));
        }
        return sb.toString();
    }

    private static void update(Digest acc, String line)
    {
        byte[] bytes = Strings.toByteArray(line);
        acc.update(bytes, 0, bytes.length);
    }

    private void check(String name, Digest acc, String expectedHex)
    {
        byte[] out = new byte[acc.getDigestSize()];
        acc.doFinal(out, 0);
        String actual = Hex.toHexString(out);
        if (!expectedHex.equals(actual))
        {
            fail(name + ": accumulated digest " + actual + " does not match the draft's " + expectedHex);
        }
    }

    public static void main(String[] args)
    {
        runTest(new SubtreeTestVectorsTest());
    }
}
