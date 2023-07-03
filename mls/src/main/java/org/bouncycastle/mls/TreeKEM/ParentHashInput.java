package org.bouncycastle.mls.TreeKEM;

import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;

import java.io.IOException;

public class ParentHashInput
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    byte[] encryptionKey;
    byte[] parentHash;
    byte[] originalSiblingTreeHash;

    public ParentHashInput(MLSInputStream stream) throws IOException
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
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOpaque(encryptionKey);
        stream.writeOpaque(parentHash);
        stream.writeOpaque(originalSiblingTreeHash);
    }
}
