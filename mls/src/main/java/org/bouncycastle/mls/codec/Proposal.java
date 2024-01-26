package org.bouncycastle.mls.codec;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.mls.TreeKEM.LeafIndex;
import org.bouncycastle.mls.TreeKEM.LeafNode;
import org.bouncycastle.mls.crypto.MlsCipherSuite;

public class Proposal
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    ProposalType proposalType;
    Add add;
    Update update;
    Remove remove;
    PreSharedKey preSharedKey;
    ReInit reInit;
    ExternalInit externalInit;
    GroupContextExtensions groupContextExtensions;

    public Add getAdd()
    {
        return add;
    }

    public Update getUpdate()
    {
        return update;
    }

    public Remove getRemove()
    {
        return remove;
    }

    public PreSharedKey getPreSharedKey()
    {
        return preSharedKey;
    }

    public ReInit getReInit()
    {
        return reInit;
    }

    public ExternalInit getExternalInit()
    {
        return externalInit;
    }

    public GroupContextExtensions getGroupContextExtensions()
    {
        return groupContextExtensions;
    }

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

    public Proposal(MLSInputStream stream)
        throws IOException
    {
        short propType = (short)stream.read(short.class);
        if (Grease.isGrease(propType) == -1)
        {
            proposalType = ProposalType.values()[propType];
        }
        else
        {
            proposalType = ProposalType.values()[8 + Grease.isGrease(propType)];
        }
        switch (proposalType)
        {
        case ADD:
            add = (Add)stream.read(Add.class);
            break;
        case UPDATE:
            update = (Update)stream.read(Update.class);
            break;
        case REMOVE:
            remove = (Remove)stream.read(Remove.class);
            break;
        case PSK:
            preSharedKey = (PreSharedKey)stream.read(PreSharedKey.class);
            break;
        case REINIT:
            reInit = (ReInit)stream.read(ReInit.class);
            break;
        case EXTERNAL_INIT:
            externalInit = (ExternalInit)stream.read(ExternalInit.class);
            break;
        case GROUP_CONTEXT_EXTENSIONS:
            groupContextExtensions = (GroupContextExtensions)stream.read(GroupContextExtensions.class);
            break;
        }
    }

    public static Proposal add(KeyPackage newMember)
        throws IOException
    {
        return new Proposal(ProposalType.ADD,
            new Add(newMember), null, null, null, null, null, null);
    }

    public static Proposal update(LeafNode leafNode)
    {
        return new Proposal(ProposalType.UPDATE, null,
            new Update(leafNode), null, null, null, null, null);
    }

    public static Proposal remove(LeafIndex removed)
    {
        return new Proposal(ProposalType.REMOVE, null, null,
            new Remove(removed), null, null, null, null);
    }

    public static Proposal preSharedKey(PreSharedKeyID pskID)
    {
        return new Proposal(ProposalType.PSK, null, null, null,
            new PreSharedKey(pskID), null, null, null);
    }

    public static Proposal reInit(byte[] group_id, ProtocolVersion version, MlsCipherSuite cipherSuite, List<Extension> extensions)
    {
        return new Proposal(ProposalType.REINIT, null, null, null, null,
            new ReInit(group_id, version, cipherSuite, extensions), null, null);
    }

    public static Proposal externalInit(byte[] kemOutput)
    {
        return new Proposal(ProposalType.EXTERNAL_INIT, null, null, null, null, null,
            new ExternalInit(kemOutput), null);
    }

    public static Proposal groupContextExtensions(List<Extension> extensions)
    {
        return new Proposal(ProposalType.GROUP_CONTEXT_EXTENSIONS, null, null, null, null, null, null,
            new GroupContextExtensions(extensions));
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
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
        public KeyPackage keyPackage;

        public Add(KeyPackage keyPackage)
            throws IOException
        {
            this.keyPackage = (KeyPackage)MLSInputStream.decode(MLSOutputStream.encode(keyPackage), KeyPackage.class);
        }

        @SuppressWarnings("unused")
        Add(MLSInputStream stream)
            throws IOException
        {
            keyPackage = (KeyPackage)stream.read(KeyPackage.class);
        }

        @Override
        public void writeTo(MLSOutputStream stream)
            throws IOException
        {
            stream.write(keyPackage);
        }
    }

    public static class Update
        implements MLSInputStream.Readable, MLSOutputStream.Writable
    {
        LeafNode leafNode;

        @SuppressWarnings("unused")
        public Update(MLSInputStream stream)
            throws IOException
        {
            leafNode = (LeafNode)stream.read(LeafNode.class);
        }

        @Override
        public void writeTo(MLSOutputStream stream)
            throws IOException
        {
            stream.write(leafNode);
        }

        public Update(LeafNode leafNode)
        {
            this.leafNode = leafNode;
        }

        public LeafNode getLeafNode()
        {
            return leafNode;
        }
    }

    public static class Remove
        implements MLSInputStream.Readable, MLSOutputStream.Writable
    {
        public LeafIndex removed;

        public Remove(LeafIndex removed)
        {
            this.removed = removed;
        }

        @SuppressWarnings("unused")
        public Remove(MLSInputStream stream)
            throws IOException
        {
            removed = (LeafIndex)stream.read(LeafIndex.class);
        }

        @Override
        public void writeTo(MLSOutputStream stream)
            throws IOException
        {
            stream.write(removed);
        }
    }

    public static class PreSharedKey
        implements MLSInputStream.Readable, MLSOutputStream.Writable
    {
        public PreSharedKeyID psk;

        @SuppressWarnings("unused")
        PreSharedKey(MLSInputStream stream)
            throws IOException
        {
            psk = (PreSharedKeyID)stream.read(PreSharedKeyID.class);
        }

        @Override
        public void writeTo(MLSOutputStream stream)
            throws IOException
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
        MlsCipherSuite suite;
        List<Extension> extensions;

        public ProtocolVersion getVersion()
        {
            return version;
        }

        public byte[] getGroupID()
        {
            return group_id;
        }

        public MlsCipherSuite getSuite()
        {
            return suite;
        }

        public List<Extension> getExtensions()
        {
            return extensions;
        }

        public ReInit(byte[] group_id, ProtocolVersion version, MlsCipherSuite cipherSuite, List<Extension> extensions)
        {
            this.group_id = group_id;
            this.version = version;
            this.suite = cipherSuite;
            this.cipherSuite = suite.getSuiteID();
            this.extensions = extensions;
        }

        @SuppressWarnings("unused")
        ReInit(MLSInputStream stream)
            throws Exception
        {
            group_id = stream.readOpaque();
            version = ProtocolVersion.values()[(short)stream.read(short.class)];
            cipherSuite = (short)stream.read(short.class);
            suite = MlsCipherSuite.getSuite(cipherSuite);
            extensions = new ArrayList<Extension>();
            stream.readList(extensions, Extension.class);
        }

        @Override
        public void writeTo(MLSOutputStream stream)
            throws IOException
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
        public byte[] kemOutput;

        @SuppressWarnings("unused")
        ExternalInit(MLSInputStream stream)
            throws IOException
        {
            kemOutput = stream.readOpaque();
        }

        @Override
        public void writeTo(MLSOutputStream stream)
            throws IOException
        {
            stream.writeOpaque(kemOutput);
        }

        public ExternalInit(byte[] kemOutput)
        {
            this.kemOutput = kemOutput.clone();
        }
    }

    public static class GroupContextExtensions
        implements MLSInputStream.Readable, MLSOutputStream.Writable
    {
        public GroupContextExtensions(List<Extension> extensions)
        {
            this.extensions = new ArrayList<Extension>();
            this.extensions.addAll(extensions);
        }

        public List<Extension> extensions;

        @SuppressWarnings("unused")
        GroupContextExtensions(MLSInputStream stream)
            throws IOException
        {
            extensions = new ArrayList<Extension>();
            stream.readList(extensions, Extension.class);
        }

        @Override
        public void writeTo(MLSOutputStream stream)
            throws IOException
        {
            stream.writeList(extensions);
        }
    }

}
