package org.bouncycastle.mls.TreeKEM;

import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.codec.NodeType;

import java.io.IOException;

public class OptionalNode
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    public static OptionalNode blankNode()
    {
        return new OptionalNode();
    }

    private OptionalNode()
    {
        this.node = null;
    }

    Node node;

    public boolean isBlank()
    {
        return node == null;
    }

    public boolean isLeaf()
    {
        return !isBlank() && node.nodeType == NodeType.leaf;
    }

    public boolean isParent()
    {
        return !isBlank() && node.nodeType == NodeType.parent;
    }

    public LeafNode getLeafNode()
    {
        return node.leafNode;
    }

    public ParentNode getParentNode()
    {
//        if (isLeaf())
//            return null;
        return node.parentNode;
    }
    public OptionalNode(MLSInputStream stream) throws IOException
    {
        node = (Node) stream.readOptional(Node.class);
    }
    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOptional(node);
    }
}
