package org.bouncycastle.mls.codec;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.mls.GroupKeySet;
import org.bouncycastle.mls.KeyGeneration;
import org.bouncycastle.mls.KeyScheduleEpoch;
import org.bouncycastle.mls.LeafIndex;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.mls.crypto.Secret;
import org.bouncycastle.mls.protocol.PreSharedKeyID;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.util.ArrayList;

public class MLSMessage
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    ProtocolVersion version;
    public WireFormat wireFormat;
    public PublicMessage publicMessage;
    public PrivateMessage privateMessage;
    Welcome welcome;
    GroupInfo groupInfo;
    KeyPackage keyPackage;

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
                break;
            case mls_group_info:
                stream.write(groupInfo);
                break;
            case mls_key_package:
                stream.write(keyPackage);
                break;
        }
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

enum WireFormat
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    RESERVED((short) 0),
    mls_public_message((short) 1),
    mls_private_message((short) 2),
    mls_welcome((short) 3),
    mls_group_info((short) 4),
    mls_key_package((short) 5);

    final short value;

    WireFormat(short value)
    {
        this.value = value;
    }

//    WireFormat(MLSInputStream stream) throws IOException
//    {
//        this.value = (short) stream.read(short.class);
//    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(value);
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


class Sender
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    SenderType senderType;
    int node_index; // leaf or sender

    public Sender(SenderType senderType, int node_index)
    {
        this.senderType = senderType;
        this.node_index = node_index;
    }
    public Sender(MLSInputStream stream) throws IOException
    {
        this.senderType = SenderType.values()[(byte) stream.read(byte.class)];
        switch (senderType)
        {

            case MEMBER:
            case EXTERNAL:
                node_index = (int) stream.read(int.class);
                break;
            case NEW_MEMBER_PROPOSAL:
            case NEW_MEMBER_COMMIT:
                break;
        }
    }
    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(senderType);
        switch (senderType)
        {
            case MEMBER:
            case EXTERNAL:
                stream.write(node_index);
                break;
            case NEW_MEMBER_PROPOSAL:
            case NEW_MEMBER_COMMIT:
                break;
        }
    }
}

class FramedContentAuthData
//    extends FramedContent
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
            stream.write(confirmation_tag);
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

class Proposal
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
        Update(MLSInputStream stream) throws IOException
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
        int removed;
        Remove(MLSInputStream stream) throws IOException
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
        CipherSuite cipherSuite;
        Extension[] extensions;
        public ReInit(byte[] group_id, ProtocolVersion version, CipherSuite cipherSuite, Extension[] extensions)
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
            extensions = (Extension[]) stream.readArray(Extension.class);
        }

        @Override
        public void writeTo(MLSOutputStream stream) throws IOException
        {
            stream.writeOpaque(group_id);
            stream.write(version);
            stream.writeArray(extensions);
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
        public GroupContextExtensions(Extension[] extensions)
        {
            this.extensions = extensions;
        }
        Extension[] extensions;

        GroupContextExtensions(MLSInputStream stream) throws IOException
        {
            extensions = (Extension[]) stream.readArray(Extension.class);
        }

        @Override
        public void writeTo(MLSOutputStream stream) throws IOException
        {
            stream.writeArray(extensions);
        }
    }

}


class Extension
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    ExtensionType extensionType;
    byte[] extension_data;

    public Extension(ExtensionType extensionType, byte[] extension_data)
    {
        this.extensionType = extensionType;
        this.extension_data = extension_data;
    }

    Extension(MLSInputStream stream) throws IOException
    {
        this.extensionType = ExtensionType.values()[(short) stream.read(short.class)];
        this.extension_data = stream.readOpaque();
    }


    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(extensionType);
        stream.writeOpaque(extension_data);
    }
}

class KeyPackage
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    ProtocolVersion version;
    CipherSuite cipher_suite;
    byte[] init_key;
    LeafNode leaf_node;
    Extension[] extensions;
    /* SignWithLabel(., "KeyPackageTBS", KeyPackageTBS) */
    byte[] signature; // KeyPackageTBS (without signature)
    KeyPackage(MLSInputStream stream) throws IOException
    {
        this.version = ProtocolVersion.values()[(short) stream.read(short.class)];
        //TODO ciphersuit

        init_key = (byte[]) stream.read(byte[].class);
        leaf_node = (LeafNode) stream.read(LeafNode.class);
        extensions = (Extension[]) stream.read(Extension.class);
        signature = stream.readOpaque();
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(version);
        stream.write(init_key);
        stream.write(leaf_node);
        stream.writeArray(extensions);
        stream.writeOpaque(signature);
    }
}

class Credential
        implements MLSInputStream.Readable, MLSOutputStream.Writable

{
    CredentialType credentialType;
    byte[] identity;
    Certificate[] certificates;
    Credential(MLSInputStream stream) throws IOException
    {
        this.credentialType = CredentialType.values()[(short) stream.read(short.class)];
        switch (credentialType)
        {
            case basic:
                identity = stream.readOpaque();
                break;
            case x509:
                certificates = (Certificate[]) stream.readArray(Certificate.class);
                break;
        }
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {

    }
}
class Certificate
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    byte[] cert_data;

    Certificate(MLSInputStream stream) throws IOException
    {
        cert_data = stream.readOpaque();
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOpaque(cert_data);
    }
}
class LeafNode
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    byte[] encryption_key;
    byte[] signature_key;
    Credential credential;
    Capabilities capabilities;
    LeafNodeSource leaf_node_source;

    //in switch
    LifeTime lifeTime;
    byte[] parent_hash;

    Extension[] extensions;
    /* SignWithLabel(., "LeafNodeTBS", LeafNodeTBS) */
    byte[] signature; // not in TBS
    LeafNode(MLSInputStream stream) throws IOException
    {
        encryption_key = (byte[]) stream.read(byte[].class);
        signature_key = (byte[]) stream.read(byte[].class);
        credential = (Credential) stream.read(Credential.class);
        capabilities = (Capabilities) stream.read(Capabilities.class);
        leaf_node_source = LeafNodeSource.values()[(short) stream.read(short.class)];
        switch (leaf_node_source)
        {
            case KEY_PACKAGE:
                lifeTime = (LifeTime) stream.read(LifeTime.class);
                break;
            case UPDATE:
                break;
            case COMMIT:
                parent_hash = stream.readOpaque();
                break;
        }
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(encryption_key);
        stream.write(signature_key);
        stream.write(credential);
        stream.write(capabilities);
        stream.write(leaf_node_source);
        switch (leaf_node_source)
        {
            case KEY_PACKAGE:
                stream.write(lifeTime);
                break;
            case UPDATE:
                break;
            case COMMIT:
                stream.writeOpaque(parent_hash);
                break;
        }
    }
}
class LifeTime
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    int not_before;
    int not_after;
    LifeTime(MLSInputStream stream) throws IOException
    {
        not_before = (int) stream.read(int.class);
        not_after = (int) stream.read(int.class);
    }

    public LifeTime(int not_before, int not_after)
    {
        this.not_before = not_before;
        this.not_after = not_after;
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(not_before);
        stream.write(not_after);
    }
}

class Capabilities
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    ProtocolVersion[] versions;
    CipherSuite[] cipherSuites;
    ExtensionType[] extensions;
    ProposalType[] proposals;
    CredentialType[] credentials;

    public Capabilities(ProtocolVersion[] versions, CipherSuite[] cipherSuites, ExtensionType[] extensions, ProposalType[] proposals, CredentialType[] credentials)
    {
        this.versions = versions;
        this.cipherSuites = cipherSuites;
        this.extensions = extensions;
        this.proposals = proposals;
        this.credentials = credentials;
    }

    Capabilities(MLSInputStream stream) throws IOException
    {
        //TODO: check might need to iterate and cast to type
        stream.readArray(ProtocolVersion.class);
        stream.readArray(CipherSuite.class);
        stream.readArray(ExtensionType.class);
        stream.readArray(ProposalType.class);
        stream.readArray(CredentialType.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeArray(versions);
        stream.writeArray(cipherSuites);
        stream.writeArray(extensions);
        stream.writeArray(proposals);
        stream.writeArray(credentials);
    }
}


enum CredentialType
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    RESERVED((byte) 0),
    basic((byte) 1),
    x509((byte) 2);

    final byte value;

    CredentialType(byte value)
    {
        this.value = value;
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        //TODO
    }
}
enum LeafNodeSource
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    RESERVED((byte) 0),
    KEY_PACKAGE((byte) 1),
    UPDATE((byte) 2),
    COMMIT((byte) 3);

    final byte value;

    LeafNodeSource(byte value)
    {
        this.value = value;
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(value);
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
enum ProposalType
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    RESERVED((short)0),
    ADD((short)1),
    UPDATE((short)2),
    REMOVE((short)3),
    PSK((short)4),
    REINIT((short)5),
    EXTERNAL_INIT((short)6),
    GROUP_CONTEXT_EXTENSIONS((short)7);
    final short value;

    ProposalType(short value)
    {
        this.value = value;
    }

    @SuppressWarnings("unused")
    ProposalType(MLSInputStream stream) throws IOException
    {
        this.value = (short) stream.read(short.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(value);
    }
}

enum SenderType
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    RESERVED((byte)0),
    MEMBER((byte)1),
    EXTERNAL((byte)2),
    NEW_MEMBER_PROPOSAL((byte)3),
    NEW_MEMBER_COMMIT((byte)4);

    final byte value;

    SenderType(byte value)
    {
        this.value = value;
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
    ProposalOrRef[] proposals;

    byte[] testProposals;
    UpdatePath updatePath;

    Commit(MLSInputStream stream) throws IOException
    {
        testProposals = stream.readOpaque();
//        proposals = (ProposalOrRef[]) stream.readArray(ProposalOrRef.class);
        updatePath = (UpdatePath) stream.readOptional(UpdatePath.class);
    }
    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeArray(proposals);
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
                reference = (byte[]) stream.readArray(byte.class);
                break;
        }
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {

    }
}

class HPKECiphertext
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    byte[] kem_output;
    byte[] ciphertext;

    public HPKECiphertext(byte[] kem_output, byte[] ciphertext)
    {
        this.kem_output = kem_output;
        this.ciphertext = ciphertext;
    }

    HPKECiphertext(MLSInputStream stream) throws IOException
    {
        kem_output = stream.readOpaque();
        ciphertext = stream.readOpaque();
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOpaque(kem_output);
        stream.writeOpaque(ciphertext);
    }
}
class UpdatePathNode
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    byte[] encryption_key;

    HPKECiphertext[] encrypted_path_secret;
    UpdatePathNode(MLSInputStream stream) throws IOException
    {
        encryption_key = (byte[]) stream.read(byte[].class);
        encrypted_path_secret = (HPKECiphertext[]) stream.read(HPKECiphertext.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {

    }
}

class UpdatePath
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    LeafNode leaf_node;
    UpdatePathNode[] nodes;

    UpdatePath(MLSInputStream stream) throws IOException
    {
        leaf_node = (LeafNode) stream.read(LeafNode.class);
        nodes = (UpdatePathNode[]) stream.readArray(UpdatePathNode.class);
    }
    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(LeafNode.class);
        stream.writeArray(nodes);
    }
}

class SenderData
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{

    LeafIndex sender;
    int leafIndex;
    int generation;
    byte[] reuseGuard;
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
        stream.write(reuseGuard);
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


class Welcome
//        implements MLSInputStream.Readable, MLSOutputStream.Writable
{

}


class GroupInfo
//        implements MLSInputStream.Readable, MLSOutputStream.Writable
{

}

