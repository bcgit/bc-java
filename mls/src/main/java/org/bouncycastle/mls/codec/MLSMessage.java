package org.bouncycastle.mls.codec;

import org.bouncycastle.mls.TreeKEM.LeafIndex;
import org.bouncycastle.mls.TreeKEM.LeafNode;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.mls.protocol.PreSharedKeyID;
import org.bouncycastle.util.Pack;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class MLSMessage
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    ProtocolVersion version;
    public WireFormat wireFormat;
    public PublicMessage publicMessage;
    public PrivateMessage privateMessage;
    public Welcome welcome;
    GroupInfo groupInfo;
    public KeyPackage keyPackage;

    public MLSMessage(MLSInputStream stream) throws IOException
    {
        this.version = ProtocolVersion.values()[(short) stream.read(short.class)];
        this.wireFormat = WireFormat.values()[(short) stream.read(short.class)];

        switch (wireFormat)
        {
            case RESERVED:
                break;
            case mls_public_message:
                this.publicMessage = (PublicMessage) stream.read(PublicMessage.class);
                break;
            case mls_private_message:
                this.privateMessage = (PrivateMessage) stream.read(PrivateMessage.class);
                break;
            case mls_welcome:
                this.welcome = (Welcome) stream.read(Welcome.class);
                break;
            case mls_group_info:
                this.groupInfo = (GroupInfo) stream.read(GroupInfo.class);
                break;
            case mls_key_package:
                this.keyPackage = (KeyPackage) stream.read(KeyPackage.class);
                break;
        }
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(version);
        stream.write(wireFormat);
        switch (wireFormat)
        {

            case RESERVED:
                break;
            case mls_public_message:
                stream.write(publicMessage);
                break;
            case mls_private_message:
                stream.write(privateMessage);
                break;
            case mls_welcome:
                stream.write(welcome);
                break;
            case mls_group_info:
                stream.write(groupInfo);
                break;
            case mls_key_package:
                stream.write(keyPackage);
                break;
        }
    }

    public ContentType getContentType()
    {
        switch (wireFormat)
        {
            case mls_public_message:
                return publicMessage.content.getContentType();
            case mls_private_message:
                return privateMessage.content_type;
            case mls_welcome:
                break;
            case mls_group_info:
                break;
            case mls_key_package:
                break;
        }
        return null;
    }
    public short getCipherSuite()
    {
        switch (wireFormat)
        {
            case mls_public_message:
            case mls_private_message:
            case mls_group_info:
                break;
            case mls_welcome:
                return welcome.cipher_suite;
            case mls_key_package:
                return keyPackage.cipher_suite;
        }
        return -1;
    }
    public long getEpoch()
    {
        switch (wireFormat)
        {

            case mls_public_message:
                return publicMessage.content.epoch;
            case mls_private_message:
                return privateMessage.epoch;
            case mls_welcome:
            case mls_group_info:
            case mls_key_package:
            default:
                //TODO: change and throw
                return -1;
        }
    }
}

enum ProtocolVersion
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    RESERVED((short) 0),
    mls10((short) 1);
    final short value;

    ProtocolVersion(short value)
    {
        this.value = value;
    }
    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(value);
    }
}

class AuthenticatedContentTBM
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    FramedContentTBS contentTBS;
    FramedContentAuthData auth;

    public AuthenticatedContentTBM(FramedContentTBS contentTBS, FramedContentAuthData auth)
    {
        this.contentTBS = contentTBS;
        this.auth = auth;
    }

    public AuthenticatedContentTBM(MLSInputStream stream) throws IOException
    {
        contentTBS = (FramedContentTBS) stream.read(FramedContentTBS.class);
        auth = (FramedContentAuthData) stream.read(FramedContentAuthData.class);
    }
    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(contentTBS);
        stream.write(auth);
    }
}


class FramedContentAuthData
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    byte[] signature;
    byte[] confirmation_tag;
    ContentType contentType;

    public FramedContentAuthData(ContentType contentType, byte[] signature, byte[] confirmation_tag)
    {
        this.signature = signature;
        this.contentType = contentType;
        switch (contentType)
        {

            case RESERVED:
            case APPLICATION:
            case PROPOSAL:
                break;
            case COMMIT:
                //TODO
                this.confirmation_tag = confirmation_tag;
                // MAYBE MAKE THIS A FUNCTION IN FRAMED CONTENT
                break;
        }
    }

    public FramedContentAuthData(MLSInputStream stream, ContentType contentType) throws IOException
    {
        this.contentType = contentType;
        signature = stream.readOpaque();
        //TODO CHECK ITS NOT OPAQUE
        if (contentType == ContentType.COMMIT)
        {
            confirmation_tag = stream.readOpaque();
        }
    }
    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOpaque(signature);
        if(contentType == ContentType.COMMIT)
        {
            stream.writeOpaque(confirmation_tag);
        }
    }
}

class FramedContentTBS
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    ProtocolVersion version = ProtocolVersion.mls10;
    WireFormat wireFormat;
    FramedContent content;
    GroupContext context;

    public FramedContentTBS(WireFormat wireFormat, FramedContent content, GroupContext context)
    {
        this.wireFormat = wireFormat;
        this.content = content;
        switch (content.sender.senderType)
        {
            case MEMBER:
            case NEW_MEMBER_COMMIT:
                this.context = context;
                break;
        }
    }
    public FramedContentTBS(WireFormat wireFormat, FramedContent content, byte[] context) throws IOException
    {
        this.wireFormat = wireFormat;
        this.content = content;
        switch (content.sender.senderType)
        {
            case MEMBER:
            case NEW_MEMBER_COMMIT:
                this.context = (GroupContext) MLSInputStream.decode(context, GroupContext.class);
                break;
        }
    }

    public FramedContentTBS(MLSInputStream stream) throws IOException
    {
        this.version = ProtocolVersion.values()[(short) stream.read(short.class)];
        this.wireFormat = WireFormat.values()[(short) stream.read(short.class)];
        this.content = (FramedContent) stream.read(FramedContent.class);
        switch (content.sender.senderType)
        {
            case MEMBER:
            case NEW_MEMBER_COMMIT:
                this.context = (GroupContext) stream.read(GroupContext.class);
                break;
            case EXTERNAL:
            case NEW_MEMBER_PROPOSAL:
                break;
        }
    }
    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(version);
        stream.write(wireFormat);
        stream.write(content);
        switch (content.sender.senderType)
        {
            case MEMBER:
            case NEW_MEMBER_COMMIT:
                stream.write(context);
                break;
            default:
                break;
        }
    }
}


enum ExtensionType
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    RESERVED((short)0),
    APPLICATION_ID((short)1),
    RATCHET_TREE((short)2),
    REQUIRED_CAPABILITIES((short)3),
    EXTERNAL_PUB((short)4),
    EXTERNAL_SENDERS((short)5);
    final short value;
    ExtensionType(short value)
    {
        this.value = value;
    }

    @SuppressWarnings("unused")
    ExtensionType(MLSInputStream stream) throws IOException
    {
        this.value = (short) stream.read(short.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(value);
    }
}

enum ProposalOrRefType
{
    RESERVED((byte) 0),
    PROPOSAL((byte) 1),
    REFERENCE((byte) 2);

    final byte value;

    ProposalOrRefType(byte value)
    {
        this.value = value;
    }
}
class Commit
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    List<ProposalOrRef> proposals;

    byte[] proposalsBytes;
    UpdatePath updatePath;

    Commit(MLSInputStream stream) throws IOException
    {
//        proposals = new ArrayList<>();
//        stream.readList(proposals ,ProposalOrRef.class);
        proposalsBytes = stream.readOpaque();
        updatePath = (UpdatePath) stream.readOptional(UpdatePath.class);
    }
    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOpaque(proposalsBytes);
//        stream.writeList(proposals);
        stream.writeOptional(updatePath);
    }
}
class ProposalOrRef
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    ProposalOrRefType type;
    Proposal proposal;

    //opaque HashReference<V>;
    //HashReference ProposalRef;
    //MakeProposalRef(value)   = RefHash("MLS 1.0 Proposal Reference", value)
    //RefHash(label, value) = Hash(RefHashInput)
    //For a ProposalRef, the value input is the AuthenticatedContent carrying the proposal.

    // opaque reference = RefHash("MLS 1.0 Proposal Reference", auth.proposal
    byte[] reference; // TODO ProposalRef

    ProposalOrRef(MLSInputStream stream) throws IOException
    {
        this.type = ProposalOrRefType.values()[(byte) stream.read(byte.class)];
        switch (type)
        {
            case PROPOSAL:
                proposal = (Proposal) stream.read(Proposal.class);
                break;
            case REFERENCE:
                //TODO
                reference = stream.readOpaque();
                break;
        }
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {

    }
}

class SenderData
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{

    LeafIndex sender;
    int leafIndex;
    int generation;
    byte[] reuseGuard;

    public SenderData(int leafIndex, int generation, byte[] reuseGuard)
    {
        this.leafIndex = leafIndex;
        this.sender = new LeafIndex(leafIndex);
        this.generation = generation;
        this.reuseGuard = reuseGuard;
    }

    SenderData(MLSInputStream stream) throws IOException
    {
        leafIndex = (int) stream.read(int.class);
        sender = new LeafIndex(leafIndex);
        generation = (int) stream.read(int.class);
        reuseGuard = Pack.intToBigEndian((int)stream.read(int.class));
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(leafIndex);
        stream.write(generation);
        stream.write(Pack.bigEndianToInt(reuseGuard, 0));
    }
}
class SenderDataAAD
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    byte[] group_id;
    long epoch;
    ContentType contentType;

    public SenderDataAAD(byte[] group_id, long epoch, ContentType contentType)
    {
        this.group_id = group_id;
        this.epoch = epoch;
        this.contentType = contentType;
    }

    SenderDataAAD(MLSInputStream stream) throws IOException
    {
        group_id = stream.readOpaque();
        epoch = (long) stream.read(long.class);
        this.contentType = ContentType.values()[(byte) stream.read(byte.class)];
    }


    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOpaque(group_id);
        stream.write(epoch);
        stream.write(contentType);
    }
}

class PrivateMessageContent
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    byte[] application_data;
    Proposal proposal;
    Commit commit;

    ContentType contentType;

    FramedContentAuthData auth;
    byte[] padding;

    PrivateMessageContent(MLSInputStream stream, ContentType contentType) throws IOException
    {
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
        auth = (FramedContentAuthData) stream.read(FramedContentAuthData.class);
        padding = stream.readOpaque();
    }


    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        switch (contentType)
        {

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
        stream.write(auth);
        stream.writeOpaque(padding);
    }
}
class PrivateContentAAD
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    byte[] group_id;
    long epoch;
    ContentType content_type;
    byte[] authenticated_data;

    public PrivateContentAAD(byte[] group_id, long epoch, ContentType content_type, byte[] authenticated_data)
    {
        this.group_id = group_id;
        this.epoch = epoch;
        this.content_type = content_type;
        this.authenticated_data = authenticated_data;
    }

    PrivateContentAAD(MLSInputStream stream) throws IOException
    {
        group_id = stream.readOpaque();
        epoch = (long) stream.read(long.class);
        content_type = ContentType.values()[(byte) stream.read(byte.class)];
        authenticated_data = stream.readOpaque();
    }
    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOpaque(group_id);
        stream.write(epoch);
        stream.write(content_type);
        stream.writeOpaque(authenticated_data);
    }
}


class EncryptedGroupSecrets
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{

    byte[] new_member; // KeyPackageRaf
    HPKECiphertext encrypted_group_secrets;


    EncryptedGroupSecrets(MLSInputStream stream) throws IOException
    {
        new_member = stream.readOpaque();
        encrypted_group_secrets = (HPKECiphertext) stream.read(HPKECiphertext.class);
    }
    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOpaque(new_member);
        stream.write(encrypted_group_secrets);
    }
}


