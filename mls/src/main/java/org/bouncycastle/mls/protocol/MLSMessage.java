package org.bouncycastle.mls.protocol;

import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.crypto.CipherSuite;

import java.io.IOException;

public class MLSMessage
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    WireFormat wireFormat;
    PublicMessage publicMessage;
    PrivateMessage privateMessage;
    Welcome welcome;
    GroupInfo groupInfo;
    KeyPackage keyPackage;
    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        switch (wireFormat)
        {

            case RESERVED:
                break;
            case mls_public_message:

                //FramedContent
                stream.writeOpaque(publicMessage.content.group_id);
                stream.write(publicMessage.content.epoch);
                    //Sender
//                stream.writeOpaque(publicMessage.content.sender);
                //FramedContentAuthData
//                switch (publicMessage.)
                //membership_tag

                break;
            case mls_private_message:
                break;
            case mls_welcome:
                break;
            case mls_group_info:
                break;
            case mls_key_package:
                break;
        }
    }
}

class PublicMessage
//        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    FramedContent content;
    FramedContentAuthData auth;
    byte[] membership_tag;

    public PublicMessage(FramedContent content, FramedContentAuthData auth, byte[] membership_tag)
    {
        this.content = content;
        this.auth = auth;
        switch (content.sender.senderType)
        {

            case RESERVED:
            case NEW_MEMBER_COMMIT:
            case EXTERNAL:
            case NEW_MEMBER_PROPOSAL:
                break;
            case MEMBER:
                this.membership_tag = membership_tag;
                break;
        }
    }

//    @Override
//    public void writeTo(MLSOutputStream stream) throws IOException
//    {
//
//    }
}


class Sender
//        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    SenderType senderType;
    int node_index; // leaf or sender

    public Sender(SenderType senderType, int node_index)
    {
        this.senderType = senderType;
        this.node_index = node_index;
    }
}

class FramedContentAuthData
    extends FramedContent
//        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    byte[] signature;
    byte[] confirmation_tag;

    public FramedContentAuthData(byte[] data, ContentType contentType, byte[] signature, byte[] confirmation_tag)
    {
        super(data, contentType);
        this.signature = signature;
        switch (contentType)
        {

            case RESERVED:
            case APPLICATION:
            case PROPOSAL:
                break;
            case COMMIT:
                this.confirmation_tag = confirmation_tag;
                break;
        }
    }
}

class FramedContent
//        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    byte[] group_id;
    long epoch;
    Sender sender;
    byte[] authenticated_data;
    byte[] application_data;

    final ContentType content_type;

    FramedContent(byte[] data, ContentType contentType)
    {
        this.content_type = contentType;
        switch (this.content_type)
        {
            case APPLICATION:
                application_data = data;
                break;
            case PROPOSAL:
            Proposal proposal;
                break;
            case COMMIT:
                Commit commit;
                break;
        }
    }
}
class Proposal
//        implements MLSInputStream.Readable, MLSOutputStream.Writable
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

    public static class Add
    {
        KeyPackage keyPackage;

        public Add(KeyPackage keyPackage)
        {
            this.keyPackage = keyPackage;
        }
    }
    public static class Update
    {
        LeafNode leafNode;

        public Update(LeafNode leafNode)
        {
            this.leafNode = leafNode;
        }
    }
    public static class Remove
    {
        int removed;

        public Remove(int removed)
        {
            this.removed = removed;
        }
    }
    public static class PreSharedKey
    {
        PreSharedKeyID psk;

        public PreSharedKey(PreSharedKeyID psk)
        {
            this.psk = psk;
        }
    }
    public static class ReInit
    {
        byte[] group_id;
        int version = 1;
        CipherSuite cipherSuite;
        Extension extension;

        public ReInit(byte[] group_id, int version, CipherSuite cipherSuite, Extension extension)
        {
            this.group_id = group_id;
            this.version = version;
            this.cipherSuite = cipherSuite;
            this.extension = extension;
        }
    }
    public static class ExternalInit
    {
        byte[] kemOutput;

        public ExternalInit(byte[] kemOutput)
        {
            this.kemOutput = kemOutput;
        }
    }
    public static class GroupContextExtensions
    {
        Extension[] extensions;

        public GroupContextExtensions(Extension[] extensions)
        {
            this.extensions = extensions;
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

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOpaque(extension_data);
    }
}

class KeyPackage
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    int version = 1; // MLSVERSION
    CipherSuite cipher_suite;
    byte[] init_key;
    LeafNode leaf_node;
    Extension extensions;
    /* SignWithLabel(., "KeyPackageTBS", KeyPackageTBS) */
    byte[] signature; // KeyPackageTBS (without signature)

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        //TODO:
    }
}

class Credential
{
    CredentialType credentialType;
    byte[] identity;
    Certificate[] certificates;

}
class Certificate
{
    byte[] cert_data;

}
class LeafNode
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
}
class LifeTime
{
    int not_before;
    int not_after;

    public LifeTime(int not_before, int not_after)
    {
        this.not_before = not_before;
        this.not_after = not_after;
    }
}

class Capabilities
{
    int[] versions;
    CipherSuite[] cipherSuites;
    ExtensionType[] extensions;
    ProposalType[] proposals;
    CredentialType[] credentials;

    public Capabilities(int[] versions, CipherSuite[] cipherSuites, ExtensionType[] extensions, ProposalType[] proposals, CredentialType[] credentials)
    {
        this.versions = versions;
        this.cipherSuites = cipherSuites;
        this.extensions = extensions;
        this.proposals = proposals;
        this.credentials = credentials;
    }
}
enum WireFormat implements MLSInputStream.Readable, MLSOutputStream.Writable
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

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(value);
    }
}

enum CredentialType implements MLSInputStream.Readable, MLSOutputStream.Writable
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
enum LeafNodeSource implements MLSInputStream.Readable, MLSOutputStream.Writable
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
enum ContentType implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    RESERVED((byte)0),
    APPLICATION((byte)1),
    PROPOSAL((byte)2),
    COMMIT((byte)3);

    final byte value;

    ContentType(byte value)
    {
        this.value = value;
    }

    @SuppressWarnings("unused")
    ContentType(MLSInputStream stream) throws IOException
    {
        this.value = (byte) stream.read(byte.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(value);
    }
}
enum ExtensionType implements MLSInputStream.Readable, MLSOutputStream.Writable
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
        this.value = (byte) stream.read(byte.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(value);
    }
}
enum ProposalType implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    ADD((short)0),
    UPDATE((short)1),
    REMOVE((short)2),
    PSK((short)3),
    REINIT((short)4),
    EXTERNAL_INIT((short)5),
    GROUP_CONTEXT_EXTENSIONS((short)6);
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
//        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    ProposalOrRef[] proposals;

}
class ProposalOrRef
//        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    ProposalOrRefType type;
    Proposal proposal;
    byte[] reference; // TODO ProposalRef
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

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOpaque(kem_output);
        stream.writeOpaque(ciphertext);
    }
}
class UpdatePathNode
{
        byte[] encryption_key;
        HPKECiphertext[] encrypted_path_secret;
}

class UpdatePath
{
    LeafNode leaf_node;
    UpdatePathNode[] nodes;
}

class PrivateMessage
//        implements MLSInputStream.Readable, MLSOutputStream.Writable
{

}


class Welcome
//        implements MLSInputStream.Readable, MLSOutputStream.Writable
{

}


class GroupInfo
//        implements MLSInputStream.Readable, MLSOutputStream.Writable
{

}

