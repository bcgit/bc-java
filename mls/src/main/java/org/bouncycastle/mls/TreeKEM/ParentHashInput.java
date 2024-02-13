package org.bouncycastle.mls.TreeKEM;

import java.io.IOException;

import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;

public class ParentHashInput
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    byte[] encryptionKey;
    byte[] parentHash;
    byte[] originalSiblingTreeHash;

    @SuppressWarnings("unused")
    public ParentHashInput(MLSInputStream stream)
        throws IOException
    {
        encryptionKey = stream.readOpaque();
        parentHash = stream.readOpaque();
        originalSiblingTreeHash = stream.readOpaque();
    }

    public ParentHashInput(byte[] encryptionKey, byte[] parentHash, byte[] originalSiblingTreeHash)
    {
        this.encryptionKey = encryptionKey;
        this.parentHash = parentHash;
        this.originalSiblingTreeHash = originalSiblingTreeHash;
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.writeOpaque(encryptionKey);
        stream.writeOpaque(parentHash);
        stream.writeOpaque(originalSiblingTreeHash);
    }
}
