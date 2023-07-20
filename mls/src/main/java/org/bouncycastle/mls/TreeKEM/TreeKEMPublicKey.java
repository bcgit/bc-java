package org.bouncycastle.mls.TreeKEM;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.mls.TreeSize;
import org.bouncycastle.mls.codec.HPKECiphertext;
import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.codec.UpdatePath;
import org.bouncycastle.mls.codec.UpdatePathNode;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.mls.crypto.Secret;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.bouncycastle.mls.TreeKEM.Utils.removeLeaves;

class FilteredDirectPath
{
    ArrayList<NodeIndex> parents;
    ArrayList<ArrayList<NodeIndex>> resolutions;

    public FilteredDirectPath clone()
    {
        FilteredDirectPath fdp = new FilteredDirectPath();
        fdp.parents = (ArrayList<NodeIndex>) parents.clone();
        fdp.resolutions = (ArrayList<ArrayList<NodeIndex>>) resolutions.clone();
        return fdp;
    }

    public FilteredDirectPath()
    {
        this.parents = new ArrayList<>();
        this.resolutions = new ArrayList<>();
    }
    public void reverse()
    {
        Collections.reverse(parents);
        Collections.reverse(resolutions);
    }

}

public class TreeKEMPublicKey
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    CipherSuite suite;
    public TreeSize size;
    Map<NodeIndex, byte[]> hashes;
    private final Map<NodeIndex, byte[]> treeHashCache;
    private final Map<NodeIndex, Integer> exceptCache;
    ArrayList<OptionalNode> nodes;

    public static TreeKEMPublicKey clone(TreeKEMPublicKey other) throws IOException
    {
        TreeKEMPublicKey tree = (TreeKEMPublicKey) MLSInputStream.decode(MLSOutputStream.encode(other), TreeKEMPublicKey.class);
        tree.setSuite(other.suite);
        tree.setHashAll();
        return tree;
    }

    public TreeKEMPublicKey(MLSInputStream stream) throws IOException
    {
        hashes = new HashMap<>();
        nodes = new ArrayList<>();
        treeHashCache = new HashMap<>();
        exceptCache = new HashMap<>();
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

    public void dumpHashes()
    {
        for (NodeIndex n : hashes.keySet())
        {
            System.out.print(n.value() + " : ");
            System.out.println(Hex.toHexString(hashes.get(n)));
        }
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

    //TODO: include leaf node options
    public TreeKEMPrivateKey update(LeafIndex from, Secret leafSecret, byte[] groupId, byte[] sigPriv) throws Exception
    {
        // Grab information about the sender
        OptionalNode leafNode = nodeAt(from);
        if (leafNode.isBlank())
        {
            throw new Exception("Cannot update from blank node");
        }

        // Generate path secrets
        TreeKEMPrivateKey priv = TreeKEMPrivateKey.create(this, from, leafSecret);
        FilteredDirectPath dp = getFilteredDirectPath(new NodeIndex(from));

        // Encrypt path secrets to the copath, forming a stub UpdatePath with no
        // encryptions
        ArrayList<UpdatePathNode> pathNodes = new ArrayList<>();
        for (NodeIndex n: dp.parents)
        {
            Secret pathSecret = priv.pathSecrets.get(n);
            AsymmetricCipherKeyPair nodePriv = priv.getPrivateKey(n);

            pathNodes.add(new UpdatePathNode(suite.getHPKE().serializePublicKey(nodePriv.getPublic()), new ArrayList<>()));
        }

        // Update and re-sign the leaf_node
        byte[][] ph = parentHashes(from, dp, pathNodes);
        byte[] ph0 = new byte[0];
        if (ph.length != 0)
        {
            ph0 = ph[0];
        }

        byte[] leafPub = suite.getHPKE().serializePublicKey(priv.getPrivateKey(new NodeIndex(from)).getPublic());
        LeafNode newLeaf = leafNode.getLeafNode().forCommit(suite, groupId, from, leafPub, ph0, sigPriv);

        // Merge the changes into the tree
        merge(from, new UpdatePath(newLeaf, pathNodes));

        return priv;
    }

    public UpdatePath encap(TreeKEMPrivateKey priv, byte[] context, List<LeafIndex> except) throws IOException, InvalidCipherTextException
    {
        FilteredDirectPath dp = getFilteredDirectPath(new NodeIndex(priv.index));
        List<UpdatePathNode> pathNodes = new ArrayList<>();
        for (int i = 0; i < dp.parents.size(); i++)
        {
            NodeIndex n = dp.parents.get(i);
            List<NodeIndex> res = dp.resolutions.get(i);
            removeLeaves(res, except);

            Secret pathSecret = priv.pathSecrets.get(n);
            AsymmetricCipherKeyPair nodePriv = priv.getPrivateKey(n);

            List<HPKECiphertext> cts = new ArrayList<>();
            for (NodeIndex nr: res)
            {
                byte[] nodePub = nodeAt(nr).node.getPublicKey();
                byte[][] ctAndEnc = suite.encryptWithLabel(nodePub, "UpdatePathNode", context, pathSecret.value());
                HPKECiphertext ct = new HPKECiphertext(ctAndEnc[1], ctAndEnc[0]);
                cts.add(ct);
            }
            pathNodes.add(new UpdatePathNode(suite.getHPKE().serializePublicKey(nodePriv.getPublic()), cts));
        }
        LeafNode newLeaf = getLeafNode(priv.index);
        return new UpdatePath(newLeaf, pathNodes);
    }

    public byte[] getRootHash() throws Exception
    {
        NodeIndex r = NodeIndex.root(size);
        if (!hashes.containsKey(r))
        {
            throw new Exception("Root hash not set");
        }

        return hashes.get(r);
    }

    public void merge(LeafIndex from, UpdatePath path) throws Exception
    {
        nodeAt(from).node = new Node(path.leaf_node);

        FilteredDirectPath dp = getFilteredDirectPath(new NodeIndex(from));

        if (dp.parents.size() != path.nodes.size())
        {
            throw new Exception("Malformed direct path");
        }

        byte[][] ph = parentHashes(from, dp, path.nodes);
        for (int i = 0; i < dp.parents.size(); i++)
        {
            NodeIndex n = dp.parents.get(i);

            byte[] parentHash = new byte[0];
            if (i < dp.parents.size() - 1)
            {
                parentHash = ph[i + 1];
            }

            nodeAt(n).node = new Node(new ParentNode(path.nodes.get(i).encryption_key, parentHash, new ArrayList<>()));
        }

        clearHashPath(from);
        setHashAll();
    }

    public boolean hasLeaf(LeafIndex index)
    {
        return !nodeAt(index).isBlank();
    }

    protected FilteredDirectPath getFilteredCommonDirectPath(LeafIndex leaf1, LeafIndex leaf2)
    {
        FilteredDirectPath xPath = getFilteredDirectPath(new NodeIndex(leaf1));
        FilteredDirectPath yPath = getFilteredDirectPath(new NodeIndex(leaf2));
        xPath.reverse();
        yPath.reverse();

        FilteredDirectPath commonPath = new FilteredDirectPath();
        for (int i = 0; i < xPath.parents.size(); i++)
        {
            if (xPath.parents.get(i).value() == yPath.parents.get(i).value())
            {
                commonPath.parents.add(xPath.parents.get(i));
                commonPath.resolutions.add(yPath.resolutions.get(i));
            }
            else
            {
                break;
            }
        }
        commonPath.reverse();
        return commonPath;
    }

    protected FilteredDirectPath getFilteredDirectPath(NodeIndex index)
    {
        FilteredDirectPath fdp = new FilteredDirectPath();
        //TODO: Why is the leafindex copath different than nodeindex copath
//        LeafIndex i = new LeafIndex(index);
        List<NodeIndex> cp = index.copath(size);

        for (NodeIndex n : cp)
        {
            NodeIndex p = n.parent();
            ArrayList<NodeIndex> res = resolve(n);

            if (res.isEmpty())
            {
                continue;
            }

            fdp.parents.add(p);
            fdp.resolutions.add(res);
        }
        return fdp;
    }

    public LeafNode getLeafNode(LeafIndex index)
    {
        OptionalNode node = nodeAt(index);
        if(!node.isLeaf())
        {
            return null;
        }

        return node.getLeafNode();
    }

    public ArrayList<NodeIndex> resolve(NodeIndex index)
    {
        boolean atLeaf = (index.level() == 0);
        if (!nodeAt(index).isBlank())
        {
            ArrayList<NodeIndex> out = new ArrayList<>();
            out.add(index);
            if(index.isLeaf())
            {
                return out;
            }

            OptionalNode node = nodeAt(index);
            List<LeafIndex> unmerged = node.getParentNode().unmerged_leaves;

            for (LeafIndex lindex : unmerged)
            {
                out.add(new NodeIndex(lindex));
            }
            return out;
        }

        if(atLeaf)
        {
            return new ArrayList<>();
        }

        ArrayList<NodeIndex> l = resolve(index.left());
        ArrayList<NodeIndex> r = resolve(index.right());

        l.addAll(r);
        return l;
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

    OptionalNode nodeAt(NodeIndex n)
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

    private byte[][] parentHashes(LeafIndex from, FilteredDirectPath fdp, List<UpdatePathNode> nodes) throws Exception
    {
        NodeIndex fromNode = new NodeIndex(from);
        FilteredDirectPath dp = fdp.clone();

        // removing root from fdp
        dp.parents.remove(dp.parents.size()-1);
        dp.resolutions.remove(dp.resolutions.size()-1);

        // special case of one-leaf tree
        if (!fromNode.equals(NodeIndex.root(size)))
        {
            dp.parents.add(0, fromNode);
            dp.resolutions.add(0, new ArrayList<>());
        }

        if (dp.parents.size() != nodes.size())
        {
            throw new Exception("Malformed UpdatePath");
        }

        // Parent hash for all the parents, starting from the root
        NodeIndex last = NodeIndex.root(size);
        byte[] lastHash = new byte[0];
        byte[][] ph = new byte[dp.parents.size()][];

        for (int i = dp.parents.size() - 1; i >= 0; i--)
        {
            NodeIndex n = dp.parents.get(i);
            NodeIndex s = n.sibling(last);

            ParentNode parentNode = new ParentNode(nodes.get(i).encryption_key, lastHash, new ArrayList<>());
            lastHash = getParentHash(parentNode, s);
            ph[i] = lastHash;

            last = n;
        }

        return ph;
    }
    private byte[] getParentHash(ParentNode parent, NodeIndex cpChild) throws Exception
    {
        if (!hashes.containsKey(cpChild))
        {
            throw new Exception("Child hash not set");
        }

        ParentHashInput hashInput = new ParentHashInput(
                parent.encryptionKey,
                parent.parentHash,
                hashes.get(cpChild)
        );

        return suite.hash(MLSOutputStream.encode(hashInput));
    }
    public boolean verifyParentHash(LeafIndex from, UpdatePath path) throws Exception
    {
        FilteredDirectPath fdp = getFilteredDirectPath(new NodeIndex(from));
        byte[][] hashChain = parentHashes(from, fdp, path.nodes);
        if (hashChain.length == 0)
        {
            return path.leaf_node.leaf_node_source != LeafNodeSource.COMMIT;
        }
        return Arrays.equals(path.leaf_node.parent_hash, hashChain[0]);
    }
    public boolean verifyParentHash() throws IOException
    {
        long width = size.width();
        long height = NodeIndex.root(size).level();

        for (int level = 1; level <= height ; level++)
        {
            long stride = 2L << level;
            int start = (int) ((stride >>> 1)-1);

            for (int p = start; p < width; p += stride)
            {
                NodeIndex pIndex = new NodeIndex(p);
                if (nodeAt(pIndex).isBlank())
                {
                    continue;
                }

                NodeIndex l = pIndex.left();
                NodeIndex r = pIndex.right();

                byte[] lh = originalParentHash(pIndex, r);
                byte[] rh = originalParentHash(pIndex, l);

                if (!hasParentHash(l, lh) && !hasParentHash(r, rh))
                {
                    dump();
                    return false;
                }
            }
        }
        return true;
    }

    private boolean hasParentHash(NodeIndex child, byte[] targetParentHash)
    {
        ArrayList<NodeIndex> res = resolve(child);
        for (NodeIndex n: res)
        {
            if (Arrays.equals(nodeAt(n).node.getParentHash(), targetParentHash))
            {
                return true;
            }
        }
        return false;
    }

    private byte[] originalTreeHash(NodeIndex index, List<LeafIndex> parentExcept) throws IOException
    {
        List<LeafIndex> except = new ArrayList<>();
        //TODO: check adding sequence
        for (LeafIndex i: parentExcept)
        {
            NodeIndex n = new NodeIndex(i);
            if (n.isBelow(index))
            {
                except.add(i);
            }
        }
        boolean haveLocalChanges = ! except.isEmpty();

        // If there are no local changes, then we can use the cached tree hash
        if (!haveLocalChanges)
        {
            return hashes.get(index);
        }

        // If this method has been called before with the same number of excluded
        // leaves (which implies the same set), then use the cached value.
        if (treeHashCache.containsKey(index))
        {
            if (exceptCache.get(index) == except.size())
            {
                return treeHashCache.get(index);
            }
        }

        // If there is no entry in either cache, recompute the value
        byte[] hash;

        if (index.isLeaf())
        {
            // A leaf node with local changes is by definition excluded from the parent
            // hash.  So we return the hash of an empty leaf.
            LeafNodeHashInput leafHashInput = new LeafNodeHashInput(new LeafIndex(index), null);
            hash = suite.hash(MLSOutputStream.encode(TreeHashInput.forLeafNode(leafHashInput)));
        }
        else
        {
            // If there is no cached value, recalculate the child hashes with the
            // specified `except` list, removing the `except` list from
            // `unmerged_leaves`.
            ParentNodeHashInput parentHashInput = new ParentNodeHashInput(
                    null,
                    originalTreeHash(index.left(), except),
                    originalTreeHash(index.right(), except)
            );

            if (!nodeAt(index).isBlank())
            {
                parentHashInput.parentNode = nodeAt(index).getParentNode();

                //TODO: check which one runs faster (assuming the latter)
                List<LeafIndex> unmergedOriginal = new ArrayList<>(parentHashInput.parentNode.unmerged_leaves);
                parentHashInput.parentNode.unmerged_leaves.removeAll(except);
//                int end = parentHashInput.parentNode.unmerged_leaves.size();
//                for (LeafIndex leaf: parentHashInput.parentNode.unmerged_leaves)
//                {
//                    if (except.contains(leaf))
//                    {
//                        end--;
//                    }
//                    else
//                    {
//                        break;
//                    }
//                }
//                parentHashInput.parentNode.unmerged_leaves = parentHashInput.parentNode.unmerged_leaves.subList(0, end);

                hash = suite.hash(MLSOutputStream.encode(TreeHashInput.forParentNode(parentHashInput)));

                // Revert the unmerged Array
                parentHashInput.parentNode.unmerged_leaves = unmergedOriginal;
            }
            else
            {
                hash = suite.hash(MLSOutputStream.encode(TreeHashInput.forParentNode(parentHashInput)));
            }



        }

        treeHashCache.put(index, hash);
        exceptCache.put(index, except.size());
        return hash;
    }
    private byte[] originalParentHash(NodeIndex parent, NodeIndex sibling) throws IOException
    {
        ParentNode parentNode = nodeAt(parent).getParentNode();
        byte[] siblingHash =  originalTreeHash(sibling, parentNode.unmerged_leaves);
        return suite.hash(MLSOutputStream.encode(new ParentHashInput(
                parentNode.encryptionKey,
                parentNode.parentHash,
                siblingHash
        )));
    }

    public byte[] getHash(NodeIndex index) throws IOException
    {
        if (hashes.containsKey(index))
        {
            return hashes.get(index);
        }

        byte[] hashInput;
        OptionalNode node = nodeAt(index);
        if (index.level() == 0)
        {
            LeafNodeHashInput input = new LeafNodeHashInput(new LeafIndex(index), null);
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
