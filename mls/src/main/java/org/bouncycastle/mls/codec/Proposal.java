package org.bouncycastle.mls.codec;

import org.bouncycastle.mls.TreeKEM.LeafNode;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.mls.protocol.PreSharedKeyID;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Proposal
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    ProposalType proposalType;
    Add add;
    Update update;
    public Remove remove;
    PreSharedKey preSharedKey;
    ReInit reInit;
    ExternalInit externalInit;
    GroupContextExtensions groupContextExtensions;

    public LeafNode getLeafNode()
    {
        switch (proposalType)
        {
            case ADD:
                return add.keyPackage.leaf_node;
            case UPDATE:
                return update.leafNode;
        }
        return null;
    }
    public ProposalType getProposalType()
    {
        return proposalType;
    }

    public Proposal(ProposalType proposalType, Add add, Update update, Remove remove, PreSharedKey preSharedKey, ReInit reInit, ExternalInit externalInit, GroupContextExtensions groupContextExtensions)
    {
        this.proposalType = proposalType;
        this.add = add;
        this.update = update;
        this.remove = remove;
        this.preSharedKey = preSharedKey;
        this.reInit = reInit;
        this.externalInit = externalInit;
        this.groupContextExtensions = groupContextExtensions;
    }

    public Proposal(MLSInputStream stream) throws IOException
    {
        proposalType = ProposalType.values()[(short) stream.read(short.class)];
        switch (proposalType)
        {
            case ADD:
                add = (Add) stream.read(Add.class);
                break;
            case UPDATE:
                update = (Update) stream.read(Update.class);
                break;
            case REMOVE:
                remove = (Remove) stream.read(Remove.class);
                break;
            case PSK:
                preSharedKey = (PreSharedKey) stream.read(PreSharedKey.class);
                break;
            case REINIT:
                reInit = (ReInit) stream.read(ReInit.class);
                break;
            case EXTERNAL_INIT:
                externalInit = (ExternalInit) stream.read(ExternalInit.class);
                break;
            case GROUP_CONTEXT_EXTENSIONS:
                groupContextExtensions = (GroupContextExtensions) stream.read(GroupContextExtensions.class);
                break;
        }
    }

    public static Proposal add()
    {
        return null;
    }

    public static Proposal update()
    {
        return null;
    }

    public static Proposal remove()
    {
        return null;
    }

    public static Proposal preSharedKey()
    {
        return null;
    }

    public static Proposal reInit()
    {
        return null;
    }

    public static Proposal externalInit()
    {
        return null;
    }

    public static Proposal groupContextExtensions()
    {
        return null;
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(proposalType);
        switch (proposalType)
        {
            case ADD:
                stream.write(add);
                break;
            case UPDATE:
                stream.write(update);
                break;
            case REMOVE:
                stream.write(remove);
                break;
            case PSK:
                stream.write(preSharedKey);
                break;
            case REINIT:
                stream.write(reInit);
                break;
            case EXTERNAL_INIT:
                stream.write(externalInit);
                break;
            case GROUP_CONTEXT_EXTENSIONS:
                stream.write(groupContextExtensions);
                break;
        }
    }

    public static class Add
            implements MLSInputStream.Readable, MLSOutputStream.Writable
    {
        KeyPackage keyPackage;

        public Add(KeyPackage keyPackage)
        {
            this.keyPackage = keyPackage;
        }

        Add(MLSInputStream stream) throws IOException
        {
            keyPackage = (KeyPackage) stream.read(KeyPackage.class);
        }

        @Override
        public void writeTo(MLSOutputStream stream) throws IOException
        {
            stream.write(keyPackage);
        }
    }

    public static class Update
            implements MLSInputStream.Readable, MLSOutputStream.Writable
    {
        LeafNode leafNode;

        public Update(MLSInputStream stream) throws IOException
        {
            leafNode = (LeafNode) stream.read(LeafNode.class);
        }

        @Override
        public void writeTo(MLSOutputStream stream) throws IOException
        {
            stream.write(leafNode);
        }

        public Update(LeafNode leafNode)
        {
            this.leafNode = leafNode;
        }
    }

    public static class Remove
            implements MLSInputStream.Readable, MLSOutputStream.Writable
    {
        public int removed;

        public Remove(MLSInputStream stream) throws IOException
        {
            removed = (int) stream.read(int.class);
        }

        @Override
        public void writeTo(MLSOutputStream stream) throws IOException
        {
            stream.write(removed);
        }

        public Remove(int removed)
        {
            this.removed = removed;
        }
    }

    public static class PreSharedKey
            implements MLSInputStream.Readable, MLSOutputStream.Writable
    {
        PreSharedKeyID psk;

        PreSharedKey(MLSInputStream stream) throws IOException
        {
            psk = (PreSharedKeyID) stream.read(PreSharedKeyID.class);
        }

        @Override
        public void writeTo(MLSOutputStream stream) throws IOException
        {
            stream.write(psk);
        }

        public PreSharedKey(PreSharedKeyID psk)
        {
            this.psk = psk;
        }
    }

    public static class ReInit
            implements MLSInputStream.Readable, MLSOutputStream.Writable
    {
        byte[] group_id;
        ProtocolVersion version;
        short cipherSuite;
        List<Extension> extensions;

        public ReInit(byte[] group_id, ProtocolVersion version, short cipherSuite, List<Extension> extensions)
        {
            this.group_id = group_id;
            this.version = version;
            this.cipherSuite = cipherSuite;
            this.extensions = extensions;
        }

        ReInit(MLSInputStream stream) throws IOException
        {
            //TODO: ciphersuite
            group_id = stream.readOpaque();
            version = ProtocolVersion.values()[(short) stream.read(short.class)];
            cipherSuite = (short) stream.read(short.class);
            extensions = new ArrayList<>();
            stream.readList(extensions, Extension.class);
        }

        @Override
        public void writeTo(MLSOutputStream stream) throws IOException
        {
            stream.writeOpaque(group_id);
            stream.write(version);
            stream.write(cipherSuite);
            stream.writeList(extensions);
        }
    }

    public static class ExternalInit
            implements MLSInputStream.Readable, MLSOutputStream.Writable
    {
        byte[] kemOutput;

        ExternalInit(MLSInputStream stream) throws IOException
        {
            kemOutput = stream.readOpaque();
        }

        @Override
        public void writeTo(MLSOutputStream stream) throws IOException
        {
            stream.writeOpaque(kemOutput);
        }

        public ExternalInit(byte[] kemOutput)
        {
            this.kemOutput = kemOutput;
        }
    }

    public static class GroupContextExtensions
            implements MLSInputStream.Readable, MLSOutputStream.Writable
    {
        public GroupContextExtensions(List<Extension> extensions)
        {
            this.extensions = extensions;
        }

        List<Extension> extensions;

        GroupContextExtensions(MLSInputStream stream) throws IOException
        {
            extensions = new ArrayList<>();
            stream.readList(extensions, Extension.class);
        }

        @Override
        public void writeTo(MLSOutputStream stream) throws IOException
        {
            stream.writeList(extensions);
        }
    }

}
