package org.bouncycastle.mls.TreeKEM;

import org.bouncycastle.mls.TreeSize;
import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TreeKEMPublicKey
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    CipherSuite suite;
    TreeSize size;
    Map<NodeIndex, byte[]> hashes;
    ArrayList<OptionalNode> nodes;


    public TreeKEMPublicKey(MLSInputStream stream) throws IOException
    {
        hashes = new HashMap<>();
        nodes = new ArrayList<>();
        stream.readList(nodes, OptionalNode.class);

        size = TreeSize.forLeaves(1);
        while(size.width() < nodes.size())
        {
            size = TreeSize.forLeaves(size.leafCount() * 2);
        }

        while (nodes.size() < size.width())
        {
            nodes.add(OptionalNode.blankNode());
        }
    }
    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        LeafIndex cut = new LeafIndex((int)size.leafCount() - 1);
        while (cut.value > 0 && nodeAt(cut).isBlank())
        {
            cut.value -= 1;
        }
        stream.writeList(nodes.subList(0, (int)(new NodeIndex(cut)).value() + 1));
    }

    public void setSuite(CipherSuite suite)
    {
        this.suite = suite;
    }
    
    public void dump()
    {
        System.out.println("Tree:");
        for (int i = 0; i < size.width(); i++)
        {
            NodeIndex index = new NodeIndex(i);
            System.out.printf("  %03d : ", i);
            if (!nodeAt(index).isBlank())
            {
                byte[] pkRm = nodeAt(index).node.getPublicKey();
                System.out.print(Hex.toHexString(pkRm, 0, 4));
            }
            else
            {
                System.out.print("        ");
            }

            System.out.print("  | ");
            for (int j = 0; j < index.level(); j++)
            {
                System.out.print("  ");
            }

            if (!nodeAt(index).isBlank())
            {
                System.out.print("X");

                if (!index.isLeaf())
                {
                    ParentNode parent = nodeAt(index).getParentNode();
                    System.out.print(" [");
                    for (LeafIndex u : parent.unmerged_leaves)
                    {
                        System.out.print(u.value + ", ");
                    }
                    System.out.print("]");
                }
            }
            else
            {
                System.out.print("_");
            }
            System.out.println();
        }
        System.out.println("nodeCount: " + nodes.size());
    }
    
    public LeafIndex addLeaf(LeafNode leaf)
    {
        LeafIndex index = new LeafIndex(0);
        while (index.value < size.leafCount() && !nodeAt(index).isBlank())
        {
            index.value++;
        }

        // Update tree size
        if (index.value >= size.leafCount())
        {
            if (size.leafCount() == 0)
            {
                size = TreeSize.forLeaves(1);
            }
            else
            {
                size = TreeSize.forLeaves(size.leafCount() * 2);
            }
        }
        while (nodes.size() < size.width())
        {
            nodes.add(OptionalNode.blankNode());
        }
//        size = TreeSize.forLeaves(index.value);

        // Set the leaf
        nodeAt(index).node = new Node(leaf);

        List<NodeIndex> dp = index.directPath(size);

        // Update the unmerged list
        for (NodeIndex n : index.directPath(size))
        {
            if (nodeAt(n).node == null)
            {
                continue;
            }
            ParentNode parent = nodeAt(n).getParentNode();
            int insertPoint = upperBound(parent.unmerged_leaves, index);
            parent.unmerged_leaves.add(insertPoint, index);
        }

        clearHashPath(index);
        return index;
    }

    private void clearHashPath(LeafIndex index)
    {
        hashes.remove(new NodeIndex(index));
        for (NodeIndex n : index.directPath(size))
        {
            hashes.remove(n);
        }
    }

    int upperBound(List<LeafIndex> list, LeafIndex index)
    {
        int lo = 0;
        int hi = list.size() - 1;

        while (lo <= hi)
        {
            int mid = (lo + hi) / 2;

            if (list.get(mid).value <= index.value)
            {
                lo = mid + 1;
            }
            else
            {
                hi = mid - 1;
            }
        }

        return lo;
    }

    public void updateLeaf(LeafIndex index, LeafNode leaf)
    {
        blankPath(index);
        nodeAt(index).node = new Node(leaf);
        clearHashPath(index);
    }

    public void blankPath(LeafIndex index)
    {
        if (nodes.isEmpty())
        {
            return;
        }
        NodeIndex ni = new NodeIndex(index);
        nodeAt(ni).node = null;
        for (NodeIndex n :
                index.directPath(size))
        {
            nodeAt(n).node = null;
        }

        clearHashPath(index);
    }

    private OptionalNode nodeAt(LeafIndex n)
    {
        return nodeAt(new NodeIndex(n));
    }

    private OptionalNode nodeAt(NodeIndex n)
    {
        long width = size.width();
        if (n.value() >= width)
        {
            throw new InvalidParameterException("Node index not in tree");
        }
        if (n.value() >= nodes.size())
        {
            return OptionalNode.blankNode();
        }
        return nodes.get((int) n.value());
    }

    public void truncate()
    {
        long w = size.width();
        if (size.leafCount() == 0)
        {
            return;
        }

        // clear the parent hashes across blank leaves
        LeafIndex index = new LeafIndex((int)size.leafCount() - 1);
        while (index.value > 0)
        {
            if(!nodeAt(index).isBlank())
            {
                break;
            }
            clearHashPath(index);
            index.value--;
        }

        if(nodeAt(index).isBlank())
        {
            nodes.clear();
            return;
        }

        // Remove the right subtree until the tree is of minimal size
        while (size.leafCount() / 2 > index.value)
        {
            //TODO: better way of clearing from index to end
            nodes.subList(nodes.size() / 2, nodes.size()).clear();
            size = TreeSize.forLeaves(size.leafCount() / 2);
        }
    }
    public void setHashAll() throws IOException
    {
        NodeIndex r = NodeIndex.root(size);
        getHash(r);
    }

    private byte[] getHash(NodeIndex index) throws IOException
    {
        if (hashes.containsKey(index))
        {
            return hashes.get(index);
        }

        byte[] hashInput;
        OptionalNode node = nodeAt(index);
        if (index.level() == 0)
        {
            LeafNodeHashInput input = new LeafNodeHashInput(new LeafIndex((int)index.value()), null);
            if (!node.isBlank())
            {
                input.leafNode = node.getLeafNode();
            }
            hashInput = MLSOutputStream.encode(TreeHashInput.forLeafNode(input));
        }
        else
        {
            ParentNodeHashInput input = new ParentNodeHashInput(
                    null,
                    getHash(index.left()),
                    getHash(index.right())
            );
            if(!node.isBlank())
            {
                input.parentNode = node.getParentNode();
            }

            hashInput = MLSOutputStream.encode(TreeHashInput.forParentNode(input));
        }

        byte[] hash = suite.hash(hashInput);
        hashes.put(index, hash);
        return hashes.get(index);
    }
}
