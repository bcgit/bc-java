package org.bouncycastle.mls.TreeKEM;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;

public class ParentNode
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    protected byte[] encryptionKey;
    byte[] parentHash;
    List<LeafIndex> unmerged_leaves;

    public ParentNode(byte[] encryptionKey, byte[] parentHash, List<LeafIndex> unmerged_leaves)
    {
        this.encryptionKey = encryptionKey.clone();
        this.parentHash = parentHash.clone();
        this.unmerged_leaves = new ArrayList<LeafIndex>(unmerged_leaves);
    }

    @SuppressWarnings("unused")
    public ParentNode(MLSInputStream stream)
        throws IOException
    {
        encryptionKey = stream.readOpaque();
        parentHash = stream.readOpaque();
        unmerged_leaves = new ArrayList<LeafIndex>();
        stream.readList(unmerged_leaves, LeafIndex.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.writeOpaque(encryptionKey);
        stream.writeOpaque(parentHash);
        stream.writeList(unmerged_leaves);
    }
}
