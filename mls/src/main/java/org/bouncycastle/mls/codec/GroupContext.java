package org.bouncycastle.mls.codec;

import java.io.IOException;
import java.util.ArrayList;

public class GroupContext
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{

    ProtocolVersion version = ProtocolVersion.mls10;
    short ciphersuit;
    byte[] groupID;
    long epoch;
    byte[] treeHash;
    public byte[] confirmedTranscriptHash;
    ArrayList<Extension> extensions;

    public GroupContext(short ciphersuit, byte[] groupID, long epoch, byte[] treeHash, byte[] confirmedTranscriptHash, ArrayList<Extension> extensions)
    {
        this.ciphersuit = ciphersuit;
        this.groupID = groupID;
        this.epoch = epoch;
        this.treeHash = treeHash;
        this.confirmedTranscriptHash = confirmedTranscriptHash;
        this.extensions = extensions;
    }

    public GroupContext(MLSInputStream stream) throws IOException
    {
        this.version = ProtocolVersion.values()[(short) stream.read(short.class)];
        this.ciphersuit = (short) stream.read(short.class);
        this.groupID = stream.readOpaque();
        this.epoch = (long) stream.read(long.class);
        this.treeHash = stream.readOpaque();
        this.confirmedTranscriptHash = stream.readOpaque();
//        this.extensions = stream.readOpaque();
        this.extensions = new ArrayList<>();
        stream.readList(extensions, Extension.class);
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
        stream.writeList(extensions);
//        stream.writeArray(extensions);

    }
}
