package org.bouncycastle.tsp.ers;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.tsp.PartialHashtree;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.util.Arrays;

/**
 * Calculator based on the use of a left weighted binary Merkle tree created
 * on top of the partial hash tree objects provided.
 */
public class BinaryTreeRootCalculator
    implements ERSRootNodeCalculator
{
    private List<List<byte[]>> tree;

    public byte[] computeRootHash(DigestCalculator digCalc, PartialHashtree[] nodes)
    {
        SortedHashList hashes = new SortedHashList();
        for (int i = 0; i < nodes.length; i++)
        {
            byte[] left = ERSUtil.computeNodeHash(digCalc, nodes[i]);

            hashes.add(left);
        }

        List<byte[]>   hashValues = hashes.toList();

        tree = new ArrayList<List<byte[]>>();
        tree.add(hashValues);

        if (hashValues.size() > 1)
        {
            do
            {
                List newHashes = new ArrayList(hashValues.size() / 2 + 1);

                for (int i = 0; i <= hashValues.size() - 2; i += 2)
                {
                    newHashes.add(ERSUtil.calculateBranchHash(digCalc, (byte[])hashValues.get(i), (byte[])hashValues.get(i + 1)));
                }

                if (hashValues.size() % 2 == 1)
                {
                    newHashes.add(hashValues.get(hashValues.size() - 1));
                }

                tree.add(newHashes);
                hashValues = newHashes;
            }
            while (hashValues.size() > 1);
        }

        return (byte[])hashValues.get(0);
    }

    public PartialHashtree[] computePathToRoot(DigestCalculator digCalc, PartialHashtree node, int index)
    {
        List<PartialHashtree> path = new ArrayList<PartialHashtree>();
        byte[] nodeHash = ERSUtil.computeNodeHash(digCalc, node);

        path.add(node);

        int row = 0;
        while (row < tree.size() - 1)
        {
            if (index == ((List<byte[]>)tree.get(row)).size() - 1)
            {
                while (true)
                {
                    // search back in case we are the odd one at the end
                    List<byte[]> hashes = (List<byte[]>)tree.get(row + 1);
                    if (!Arrays.areEqual(nodeHash, (byte[])hashes.get(hashes.size() - 1)))
                    {
                        break;
                    }

                    row++;
                    index = ((List<byte[]>)tree.get(row)).size() - 1;
                }
            }

            byte[] neighborHash;
            if ((index & 1) == 0)
            {
                neighborHash = (byte[])((List<byte[]>)tree.get(row)).get(index + 1);
            }
            else
            {
                neighborHash = (byte[])((List<byte[]>)tree.get(row)).get(index - 1);
            }

            path.add(new PartialHashtree(neighborHash));

            nodeHash = ERSUtil.calculateBranchHash(digCalc, nodeHash, neighborHash);
            index = index / 2;
            row++;
        }

        return (PartialHashtree[])path.toArray(new PartialHashtree[0]);
    }

    public byte[] recoverRootHash(DigestCalculator digCalc, PartialHashtree[] nodes)
    {
        byte[] baseHash = ERSUtil.computeNodeHash(digCalc, nodes[0]);

        for (int i = 1; i < nodes.length; i++)
        {
            baseHash = ERSUtil.calculateBranchHash(digCalc, baseHash, ERSUtil.computeNodeHash(digCalc, nodes[i]));
        }

        return baseHash;
    }
}
