package org.bouncycastle.mls.codec;

import java.io.IOException;
import java.util.ArrayList;

public class GroupContext
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{

    ProtocolVersion version = ProtocolVersion.mls10;
    public short ciphersuite;
    public byte[] groupID;
    public long epoch;
    public byte[] treeHash;
    public byte[] confirmedTranscriptHash;
    public ArrayList<Extension> extensions;

    public GroupContext(short ciphersuit, byte[] groupID, long epoch, byte[] treeHash, byte[] confirmedTranscriptHash, ArrayList<Extension> extensions)
    {
        this.ciphersuite = ciphersuit;
        this.groupID = groupID;
        this.epoch = epoch;
        this.treeHash = treeHash;
        this.confirmedTranscriptHash = confirmedTranscriptHash;
        this.extensions = extensions;
    }

    public GroupContext(MLSInputStream stream) throws IOException
    {
        this.version = ProtocolVersion.values()[(short) stream.read(short.class)];
        this.ciphersuite = (short) stream.read(short.class);
        this.groupID = stream.readOpaque();
        this.epoch = (long) stream.read(long.class);
        this.treeHash = stream.readOpaque();
        this.confirmedTranscriptHash = stream.readOpaque();
        this.extensions = new ArrayList<>();
        stream.readList(extensions, Extension.class);
    }


    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(version);
        stream.write(ciphersuite);
        stream.writeOpaque(groupID);
        stream.write(epoch);
        stream.writeOpaque(treeHash);
        stream.writeOpaque(confirmedTranscriptHash);
        stream.writeList(extensions);

    }
}
