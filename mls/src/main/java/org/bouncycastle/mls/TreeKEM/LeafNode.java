package org.bouncycastle.mls.TreeKEM;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.mls.codec.Capabilities;
import org.bouncycastle.mls.codec.Credential;
import org.bouncycastle.mls.codec.CredentialType;
import org.bouncycastle.mls.codec.Extension;
import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.crypto.MlsCipherSuite;
import org.bouncycastle.mls.protocol.Group;

public class LeafNode
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    MlsCipherSuite suite;
    byte[] encryption_key;
    byte[] signature_key;
    Credential credential;
    Capabilities capabilities;
    LeafNodeSource leaf_node_source;

    //in switch
    LifeTime lifeTime;
    byte[] parent_hash;

    List<Extension> extensions;
    /* SignWithLabel(., "LeafNodeTBS", LeafNodeTBS) */
    byte[] signature; // not in TBS

    public Capabilities getCapabilities()
    {
        return capabilities;
    }

    public CredentialType getCredentialType()
    {
        return credential.getCredentialType();
    }

    public MlsCipherSuite getSuite()
    {
        return suite;
    }

    public LifeTime getLifeTime()
    {
        return lifeTime;
    }

    public byte[] getEncryptionKey()
    {
        return encryption_key;
    }

    public byte[] getSignatureKey()
    {
        return signature_key;
    }

    public List<Extension> getExtensions()
    {
        return extensions;
    }

    public LeafNode(
        MlsCipherSuite suite,
        byte[] encryption_key,
        byte[] signature_key,
        Credential credential,
        Capabilities capabilities,
        LifeTime lifeTime,
        List<Extension> extensions,
        byte[] sigSk)
        throws Exception
    {
        this.suite = suite;
        this.encryption_key = encryption_key;
        this.signature_key = signature_key;
        this.credential = credential;
        this.capabilities = capabilities; //TODO: grease
        this.lifeTime = lifeTime;
        this.extensions = new ArrayList<Extension>(extensions); //TODO: grease
        this.leaf_node_source = LeafNodeSource.KEY_PACKAGE; //TODO: check

        sign(suite, sigSk, toBeSigned(null, -1));
    }

    public LeafNode()
    {
    }

    public LeafNode(MLSInputStream stream)
        throws IOException
    {
        encryption_key = stream.readOpaque();
        signature_key = stream.readOpaque();
        credential = (Credential)stream.read(Credential.class);
        capabilities = (Capabilities)stream.read(Capabilities.class);
        leaf_node_source = LeafNodeSource.values()[(byte)stream.read(byte.class)];
        switch (leaf_node_source)
        {
        case KEY_PACKAGE:
            lifeTime = (LifeTime)stream.read(LifeTime.class);
            break;
        case UPDATE:
            break;
        case COMMIT:
            parent_hash = stream.readOpaque();
            break;
        }
        extensions = new ArrayList<Extension>();
        stream.readList(extensions, Extension.class);
        signature = stream.readOpaque();
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.writeOpaque(encryption_key);
        stream.writeOpaque(signature_key);
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
        stream.writeList(extensions);
        stream.writeOpaque(signature);
    }

    public LeafNodeSource getSource()
    {
        return leaf_node_source;
    }

    public Credential getCredential()
    {
        return credential;
    }

    public byte[] toBeSigned(byte[] groupId, int leafIndex)
        throws IOException
    {
        MLSOutputStream stream = new MLSOutputStream();
        stream.writeOpaque(encryption_key);
        stream.writeOpaque(signature_key);
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
        stream.writeList(extensions);
        switch (leaf_node_source)
        {
        case KEY_PACKAGE:
            break;
        case UPDATE:
        case COMMIT:
            stream.writeOpaque(groupId);
            stream.write(leafIndex);
            break;
        }
        return stream.toByteArray();
    }

    public boolean verifyExtensionSupport(List<Extension> extensions)
    {
        //TODO: Verify that extensions in the list are supported

        //TODO: Verify Required Capability extension is supported (if there is one)

        return true;
    }

    public boolean verifyLifetime()
    {
        if (leaf_node_source != LeafNodeSource.KEY_PACKAGE)
        {
            return true;
        }

        return lifeTime.verify();
    }

    public boolean verify(MlsCipherSuite suite, byte[] tbs)
        throws IOException
    {
        if (getCredentialType() == CredentialType.x509)
        {
            //TODO: get credential and check if it's signature scheme matches the cipher suite signature scheme
        }

        return suite.verifyWithLabel(signature_key, "LeafNodeTBS", tbs, signature);
    }

    public LeafNode forCommit(MlsCipherSuite suite, byte[] groupId, LeafIndex leafIndex, byte[] encKeyIn, byte[] parentHash, Group.LeafNodeOptions options, byte[] sigPriv)
        throws Exception
    {
        LeafNode clone = copyWithOptions(encKeyIn, options);
        clone.leaf_node_source = LeafNodeSource.COMMIT;
        clone.parent_hash = parentHash.clone();

        clone.sign(suite, sigPriv, clone.toBeSigned(groupId, leafIndex.value));

        return clone;
    }

    public LeafNode forUpdate(MlsCipherSuite suite, byte[] groupId, LeafIndex leafIndex, byte[] encKeyIn, Group.LeafNodeOptions options, byte[] sigPriv)
        throws Exception
    {
        LeafNode clone = copyWithOptions(encKeyIn, options);
        clone.leaf_node_source = LeafNodeSource.UPDATE;

        clone.sign(suite, sigPriv, clone.toBeSigned(groupId, leafIndex.value));

        return clone;
    }

    private void sign(MlsCipherSuite suite, byte[] sigPriv, byte[] tbs)
        throws Exception
    {
        byte[] sigPub = suite.serializeSignaturePublicKey(suite.deserializeSignaturePrivateKey(sigPriv).getPublic());
        if (!Arrays.equals(sigPub, signature_key))
        {
            throw new Exception("Signature key mismatch");
        }

        //TODO: check if credential is valid for signature key

        signature = suite.signWithLabel(sigPriv, "LeafNodeTBS", tbs);
    }


    //TODO: add options to clone with credential/capabilities/extensions
    public LeafNode copyWithOptions(byte[] encKeyIn, Group.LeafNodeOptions options)
    {
        LeafNode clone = copy(encKeyIn);
        if (options.getCredential() != null)
        {
            clone.credential = options.getCredential();
        }

        if (options.getCapabilities() != null)
        {
            clone.capabilities = options.getCapabilities();
        }

        if (options.getExtensions() != null)
        {
            clone.extensions = options.getExtensions();
        }

        return clone;
    }

    public LeafNode copy(byte[] encKeyIn)
    {
        LeafNode clone = new LeafNode();
        clone.encryption_key = encKeyIn.clone();
        clone.signature_key = this.signature_key.clone();
        clone.credential = this.credential;
        clone.capabilities = this.capabilities;
        clone.leaf_node_source = this.leaf_node_source;
        switch (clone.leaf_node_source)
        {
        case KEY_PACKAGE:
            clone.lifeTime = this.lifeTime;
            break;
        case UPDATE:
            break;
        case COMMIT:
            clone.parent_hash = this.parent_hash.clone();
            break;
        }
        clone.extensions = new ArrayList<Extension>(this.extensions);
        clone.signature = this.signature.clone();
        return clone;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }

        LeafNode leafNode = (LeafNode)o;

        //TODO: check other variables?

        if (!Arrays.equals(encryption_key, leafNode.encryption_key))
        {
            return false;
        }
        if (!Arrays.equals(signature_key, leafNode.signature_key))
        {
            return false;
        }
        return Arrays.equals(signature, leafNode.signature);
    }
}

