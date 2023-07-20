package org.bouncycastle.mls.codec;

import org.bouncycastle.mls.TreeKEM.LeafNode;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class UpdatePath
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    public LeafNode leaf_node;
    public List<UpdatePathNode> nodes;

    public UpdatePath(LeafNode leaf_node, List<UpdatePathNode> nodes)
    {
        this.leaf_node = leaf_node;
        this.nodes = new ArrayList<>(nodes);
    }

    UpdatePath(MLSInputStream stream) throws IOException
    {
        leaf_node = (LeafNode) stream.read(LeafNode.class);
        nodes = new ArrayList<>();
        stream.readList(nodes, UpdatePathNode.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(LeafNode.class);
        stream.writeList(nodes);
    }
}
