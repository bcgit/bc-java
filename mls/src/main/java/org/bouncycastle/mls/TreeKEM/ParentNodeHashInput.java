package org.bouncycastle.mls.TreeKEM;

import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;

import java.io.IOException;

public class ParentNodeHashInput
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    ParentNode parentNode;
    byte[] leftHash;
    byte[] rightHash;

    public ParentNodeHashInput(ParentNode parentNode, byte[] leftHash, byte[] rightHash)
    {
        this.parentNode = parentNode;
        this.leftHash = leftHash;
        this.rightHash = rightHash;
    }

    public ParentNodeHashInput(MLSInputStream stream) throws IOException
    {
        parentNode = (ParentNode) stream.readOptional(ParentNode.class);
        leftHash = stream.readOpaque();
        rightHash = stream.readOpaque();
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOptional(parentNode);
        stream.writeOpaque(leftHash);
        stream.writeOpaque(rightHash);
    }
}


