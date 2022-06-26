package org.bouncycastle.tsp.ers;

import java.util.List;

import org.bouncycastle.asn1.tsp.PartialHashtree;
import org.bouncycastle.operator.DigestCalculator;

/**
 * Calculator based on the use of a left weighted binary Merkle tree created
 * on top of the partial hash tree objects provided.
 */
public class BinaryTreeRootCalculator
    implements ERSRootNodeCalculator
{
    public byte[] computeRootHash(DigestCalculator digCalc, PartialHashtree[] nodes)
    {
        SortedHashList hashes = new SortedHashList();
        for (int i = 0; i < nodes.length; i++)
        {
            byte[] left = ERSUtil.computeNodeHash(digCalc, nodes[i]);

            hashes.add(left);
        }

        do
        {
            SortedHashList newHashes = new SortedHashList();
            List<byte[]>   hashValues = hashes.toList();

            for (int i = 0; i <= hashValues.size() - 2; i += 2)
            {
                newHashes.add(ERSUtil.calculateDigest(digCalc, (byte[])hashValues.get(i), (byte[])hashValues.get(i + 1)));
            }

            if (hashes.size() % 2 == 1)
            {
                newHashes.add(hashValues.get(hashes.size() - 1));
            }

            hashes = newHashes;
        }
        while (hashes.size() > 1);

        return hashes.getFirst();
    }
}
