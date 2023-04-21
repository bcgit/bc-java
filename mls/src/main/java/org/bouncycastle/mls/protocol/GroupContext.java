package org.bouncycastle.mls.protocol;

import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;

import java.io.IOException;

public class GroupContext
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{

    byte[] groupID;
    long epoch;
    byte[] treeHash;
    byte[] confirmedTranscriptHash;

    public GroupContext(byte[] groupID, long epoch, byte[] treeHash, byte[] confirmedTranscriptHash)
    {
        this.groupID = groupID;
        this.epoch = epoch;
        this.treeHash = treeHash;
        this.confirmedTranscriptHash = confirmedTranscriptHash;
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOpaque(groupID);
        stream.write(epoch);
        stream.writeOpaque(treeHash);
        stream.writeOpaque(confirmedTranscriptHash);
        // TODO: Add extensions

    }
}
