package org.bouncycastle.mls.TreeKEM;

import org.bouncycastle.mls.TreeKEM.LeafIndex;
import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ParentNode
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    protected byte[] encryptionKey;
    byte[] parentHash;
    public List<LeafIndex> unmerged_leaves;

    public ParentNode(MLSInputStream stream) throws IOException
    {
        encryptionKey = stream.readOpaque();
        parentHash = stream.readOpaque();
        unmerged_leaves = new ArrayList<>();
        stream.readList(unmerged_leaves, LeafIndex.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOpaque(encryptionKey);
        stream.writeOpaque(parentHash);
        stream.writeList(unmerged_leaves);
    }
}
