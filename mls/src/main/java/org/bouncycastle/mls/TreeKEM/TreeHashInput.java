package org.bouncycastle.mls.TreeKEM;

import java.io.IOException;

import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.codec.NodeType;

public class TreeHashInput
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    NodeType nodeType;
    LeafNodeHashInput leafNode;
    ParentNodeHashInput parentNode;

    private TreeHashInput(NodeType nodeType, LeafNodeHashInput leafNode, ParentNodeHashInput parentNode)
    {
        this.nodeType = nodeType;
        this.leafNode = leafNode;
        this.parentNode = parentNode;
    }

    public static TreeHashInput forLeafNode(LeafNodeHashInput leafNode)
    {
        return new TreeHashInput(NodeType.leaf, leafNode, null);
    }

    public static TreeHashInput forParentNode(ParentNodeHashInput parentNode)
    {
        return new TreeHashInput(NodeType.parent, null, parentNode);
    }

    @SuppressWarnings("unused")
    public TreeHashInput(MLSInputStream stream)
        throws IOException
    {
        nodeType = NodeType.values()[(byte)stream.read(byte.class)];
        switch (nodeType)
        {
        case leaf:
            leafNode = (LeafNodeHashInput)stream.read(LeafNodeHashInput.class);
            break;
        case parent:
            parentNode = (ParentNodeHashInput)stream.read(ParentNodeHashInput.class);
            break;
        }
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.write(nodeType);
        switch (nodeType)
        {
        case leaf:
            stream.write(leafNode);
            break;
        case parent:
            stream.write(parentNode);
            break;
        }
    }
}
