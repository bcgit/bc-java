package org.bouncycastle.mls.TreeKEM;

import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.codec.NodeType;

import java.io.IOException;

public class Node
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    NodeType nodeType;
    LeafNode leafNode;
    ParentNode parentNode;

    public byte[] getPublicKey()
    {
        switch (nodeType)
        {
            case leaf:
                return leafNode.encryption_key;
            case parent:
                return parentNode.encryptionKey;
        }
        return null;
    }

    public Node(LeafNode leafNode)
    {
        nodeType = NodeType.leaf;
        this.leafNode = leafNode;
    }
    public Node(ParentNode parentNode)
    {
        nodeType = NodeType.parent;
        this.parentNode = parentNode;
    }

//    public boolean isLeaf()
//    {
//        return nodeType == NodeType.leaf;
//    }
//    public boolean isParent()
//    {
//        return nodeType == NodeType.parent;
//    }
//
//    public LeafNode getLeafNode()
//    {
//        return leafNode;
//    }
//    public ParentNode getParentNode()
//    {
//        return parentNode;
//    }

    public Node(MLSInputStream stream) throws IOException
    {
        this.nodeType = NodeType.values()[(byte) stream.read(byte.class)];
        switch (nodeType)
        {
            case leaf:
                leafNode = (LeafNode) stream.read(LeafNode.class);
                break;
            case parent:
                parentNode = (ParentNode) stream.read(ParentNode.class);
                break;
        }
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
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

