package org.bouncycastle.mls.codec;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.mls.TreeKEM.LeafNode;

public class UpdatePath
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    LeafNode leaf_node;
    List<UpdatePathNode> nodes;

    public LeafNode getLeafNode()
    {
        return leaf_node;
    }

    public List<UpdatePathNode> getNodes()
    {
        return nodes;
    }

    public UpdatePath clone()
    {
        return new UpdatePath(leaf_node, nodes);
    }

    public UpdatePath(LeafNode leaf_node, List<UpdatePathNode> nodes)
    {
//        this.leaf_node = leaf_node;
        this.leaf_node = leaf_node.copy(leaf_node.getEncryptionKey());
        this.nodes = new ArrayList<UpdatePathNode>(nodes);
    }

    @SuppressWarnings("unused")
    UpdatePath(MLSInputStream stream)
        throws IOException
    {
        leaf_node = (LeafNode)stream.read(LeafNode.class);
        nodes = new ArrayList<UpdatePathNode>();
        stream.readList(nodes, UpdatePathNode.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.write(leaf_node);
        stream.writeList(nodes);
    }
}
