package org.bouncycastle.mls.protocol;

import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;

import java.io.IOException;

public class GroupContext
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{

    short version = 1;
    short ciphersuit;
    byte[] groupID;
    long epoch;
    byte[] treeHash;
    byte[] confirmedTranscriptHash;

    byte[] extensions;

    public GroupContext(short ciphersuit, byte[] groupID, long epoch, byte[] treeHash, byte[] confirmedTranscriptHash, byte[] extensions)
    {
        this.ciphersuit = ciphersuit;
        this.groupID = groupID;
        this.epoch = epoch;
        this.treeHash = treeHash;
        this.confirmedTranscriptHash = confirmedTranscriptHash;
        this.extensions = extensions;
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(version);
        stream.write(ciphersuit);
        stream.writeOpaque(groupID);
        stream.write(epoch);
        stream.writeOpaque(treeHash);
        stream.writeOpaque(confirmedTranscriptHash);
        // TODO: Add extensions
        stream.writeOpaque(extensions);

    }
}
