package org.bouncycastle.tsp.ers;

import java.util.ArrayList;
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
        List<byte[]> hashes = new ArrayList<byte[]>();
        for (int i = 0; i <= nodes.length - 2; i += 2)
        {
            byte[] left = ERSUtil.computeNodeHash(digCalc, nodes[i]);
            byte[] right = ERSUtil.computeNodeHash(digCalc, nodes[i + 1]);

            hashes.add(ERSUtil.calculateBranchHash(digCalc, left, right));
        }

        if (nodes.length % 2 == 1)
        {
            hashes.add(ERSUtil.computeNodeHash(digCalc, nodes[nodes.length - 1]));
        }

        do
        {
            List<byte[]> newHashes = new ArrayList<byte[]>((hashes.size() + 1) / 2);

            for (int i = 0; i <= hashes.size() - 2; i += 2)
            {
                newHashes.add(ERSUtil.calculateBranchHash(digCalc, (byte[])hashes.get(i), (byte[])hashes.get(i + 1)));
            }

            if (hashes.size() % 2 == 1)
            {
                newHashes.add(hashes.get(hashes.size() - 1));
            }

            hashes = newHashes;
        }
        while (hashes.size() > 1);

        return (byte[])hashes.get(0);
    }
}
