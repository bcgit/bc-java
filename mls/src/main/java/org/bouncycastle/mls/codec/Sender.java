package org.bouncycastle.mls.codec;

import java.io.IOException;

import org.bouncycastle.mls.TreeKEM.LeafIndex;

public class Sender
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    SenderType senderType;
    LeafIndex sender;
    int sender_index;

    public SenderType getSenderType()
    {
        return senderType;
    }

    public LeafIndex getSender()
    {
        return sender;
    }

    public int getSenderIndex()
    {
        return sender_index;
    }

    public static Sender forNewMemberCommit()
    {
        return new Sender(SenderType.NEW_MEMBER_COMMIT, null, -1);
    }

    public static Sender forNewMemberProposal()
    {
        return new Sender(SenderType.NEW_MEMBER_PROPOSAL, null, -1);
    }

    public static Sender forMember(LeafIndex sender)
    {
        return new Sender(SenderType.MEMBER, sender, -1);
    }

    public static Sender forExternal(int senderIndex)
    {
        return new Sender(SenderType.EXTERNAL, null, senderIndex);
    }

    public Sender(SenderType senderType, LeafIndex sender, int sender_index)
    {
        this.senderType = senderType;
        this.sender = sender;
        this.sender_index = sender_index;
    }

    @SuppressWarnings("unused")
    public Sender(MLSInputStream stream)
        throws IOException
    {
        this.senderType = SenderType.values()[(byte)stream.read(byte.class)];
        switch (senderType)
        {

        case MEMBER:
            sender = (LeafIndex)stream.read(LeafIndex.class);
            break;
        case EXTERNAL:
            sender_index = (int)stream.read(int.class);
            break;
        case NEW_MEMBER_PROPOSAL:
        case NEW_MEMBER_COMMIT:
            break;
        }
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.write(senderType);
        switch (senderType)
        {
        case MEMBER:
            stream.write(sender);
            break;
        case EXTERNAL:
            stream.write(sender_index);
            break;
        case NEW_MEMBER_PROPOSAL:
        case NEW_MEMBER_COMMIT:
            break;
        }
    }
}
