package org.bouncycastle.mls.codec;

import java.io.IOException;
import java.util.ArrayList;

import org.bouncycastle.mls.crypto.MlsCipherSuite;

public class GroupContext
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{

    ProtocolVersion version = ProtocolVersion.mls10;
    short ciphersuite;
    MlsCipherSuite suite;
    byte[] groupID;
    long epoch;
    byte[] treeHash;
    byte[] confirmedTranscriptHash;
    ArrayList<Extension> extensions;

    public byte[] getTreeHash()
    {
        return treeHash;
    }

    public byte[] getConfirmedTranscriptHash()
    {
        return confirmedTranscriptHash;
    }

    public ArrayList<Extension> getExtensions()
    {
        return extensions;
    }

    public GroupContext(MlsCipherSuite ciphersuite, byte[] groupID, long epoch, byte[] treeHash, byte[] confirmedTranscriptHash, ArrayList<Extension> extensions)
    {
        this.suite = ciphersuite;
        this.ciphersuite = ciphersuite.getSuiteID();
        this.groupID = groupID;
        this.epoch = epoch;
        this.treeHash = treeHash;
        this.confirmedTranscriptHash = confirmedTranscriptHash;
        this.extensions = new ArrayList<Extension>(extensions);
    }

    @SuppressWarnings("unused")
    public GroupContext(MLSInputStream stream)
        throws Exception
    {
        this.version = ProtocolVersion.values()[(short)stream.read(short.class)];
        this.ciphersuite = (short)stream.read(short.class);
        this.suite = MlsCipherSuite.getSuite(ciphersuite);
        this.groupID = stream.readOpaque();
        this.epoch = (long)stream.read(long.class);
        this.treeHash = stream.readOpaque();
        this.confirmedTranscriptHash = stream.readOpaque();
        this.extensions = new ArrayList<Extension>();
        stream.readList(extensions, Extension.class);
    }


    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
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
