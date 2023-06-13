package org.bouncycastle.mls.codec;

import java.io.IOException;

public class FramedContent
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    byte[] group_id;
    long epoch;
    Sender sender;
    byte[] authenticated_data;
    byte[] application_data;

    final ContentType contentType;

    Proposal proposal;
    Commit commit;

    public byte[] getContentBytes() throws IOException
    {
        switch (contentType)
        {

            case APPLICATION:
                return application_data;
            case PROPOSAL:
                return MLSOutputStream.encode(proposal);
            case COMMIT:
                return MLSOutputStream.encode(commit);
            default:
                return null;
        }
    }

    public FramedContent(MLSInputStream stream) throws IOException
    {
        group_id = stream.readOpaque();
        epoch = (long) stream.read(long.class);
        sender = (Sender) stream.read(Sender.class);
        authenticated_data = stream.readOpaque();
        contentType = ContentType.values()[(byte) stream.read(byte.class)];
        switch (contentType)
        {
            case APPLICATION:
                application_data = stream.readOpaque();
                break;
            case PROPOSAL:
                proposal = (Proposal) stream.read(Proposal.class);
                break;
            case COMMIT:
                commit = (Commit) stream.read(Commit.class);
                break;
        }
    }

    FramedContent(byte[] group_id, long epoch, Sender sender, byte[] authenticated_data, byte[] application_data, ContentType content_type, Proposal proposal, Commit commit)
    {
        this.group_id = group_id;
        this.epoch = epoch;
        this.sender = sender;
        this.authenticated_data = authenticated_data;
        this.application_data = application_data;
        this.contentType = content_type;
        this.proposal = proposal;
        this.commit = commit;
    }
    FramedContent(byte[] group_id, long epoch, Sender sender, byte[] authenticated_data, ContentType content_type)
    {
        this.group_id = group_id;
        this.epoch = epoch;
        this.sender = sender;
        this.authenticated_data = authenticated_data;
        this.contentType = content_type;
        switch (contentType)
        {
            case APPLICATION:
                this.application_data = new byte[0];
                break;
            case PROPOSAL:
//                this.proposal = new Proposal();
                break;
            case COMMIT:
                break;
        }
    }

    public static FramedContent application(byte[] group_id, long epoch, Sender sender, byte[] authenticated_data, byte[] application_data)
    {
        return new FramedContent(group_id, epoch, sender, authenticated_data, application_data, ContentType.APPLICATION, null, null);
    }

    public static FramedContent proposal(byte[] group_id, long epoch, Sender sender, byte[] authenticated_data, Proposal proposal)
    {
        return new FramedContent(group_id, epoch, sender, authenticated_data, null, ContentType.PROPOSAL, proposal, null);
    }

    public static FramedContent commit(byte[] group_id, long epoch, Sender sender, byte[] authenticated_data, Commit commit)
    {
        return new FramedContent(group_id, epoch, sender, authenticated_data, null, ContentType.COMMIT, null, commit);
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOpaque(group_id);
        stream.write(epoch);
        stream.write(sender);
        stream.writeOpaque(authenticated_data);
        stream.write(contentType);

        switch (contentType)
        {
            case RESERVED:
                break;
            case APPLICATION:
                stream.writeOpaque(application_data);
                break;
            case PROPOSAL:
                stream.write(proposal);
                break;
            case COMMIT:
                stream.write(commit);
                break;
        }
    }
}
