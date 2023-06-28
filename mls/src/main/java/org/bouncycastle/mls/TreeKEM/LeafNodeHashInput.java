package org.bouncycastle.mls.TreeKEM;

import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;

import java.io.IOException;

public class LeafNodeHashInput
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    LeafIndex leafIndex;
    LeafNode leafNode;

    public LeafNodeHashInput(LeafIndex leafIndex, LeafNode leafNode)
    {
        this.leafIndex = leafIndex;
        this.leafNode = leafNode;
    }

    public LeafNodeHashInput(MLSInputStream stream) throws IOException
    {
        leafIndex = (LeafIndex) stream.read(LeafIndex.class);
        leafNode = (LeafNode) stream.readOptional(LeafIndex.class);
    }
    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(leafIndex);
        stream.writeOptional(leafNode);
    }
}
