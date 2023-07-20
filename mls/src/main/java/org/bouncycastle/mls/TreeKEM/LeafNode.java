package org.bouncycastle.mls.TreeKEM;

import org.bouncycastle.mls.codec.Capabilities;
import org.bouncycastle.mls.codec.Credential;
import org.bouncycastle.mls.codec.CredentialType;
import org.bouncycastle.mls.codec.Extension;
import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.crypto.CipherSuite;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class LeafNode
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

    List<Extension> extensions;
    /* SignWithLabel(., "LeafNodeTBS", LeafNodeTBS) */
    byte[] signature; // not in TBS

    public LeafNode()
    {
    }

    public LeafNode(MLSInputStream stream) throws IOException
    {
        encryption_key = stream.readOpaque();
        signature_key = stream.readOpaque();
        credential = (Credential) stream.read(Credential.class);
        capabilities = (Capabilities) stream.read(Capabilities.class);
        leaf_node_source = LeafNodeSource.values()[(byte) stream.read(byte.class)];
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
        extensions = new ArrayList<>();
        stream.readList(extensions, Extension.class);
        signature = stream.readOpaque();


    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
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
    public byte[] toBeSigned(byte[] groupId, int leafIndex) throws IOException
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

    public boolean verify(CipherSuite suite, byte[] tbs) throws IOException
    {
        if (credential.credentialType == CredentialType.x509)
        {
            //TODO: get credential and check if it's signature scheme matches the cipher suite signature scheme
        }

        return suite.verifyWithLabel(signature_key, "LeafNodeTBS", tbs, signature);
    }

    public LeafNode forCommit(CipherSuite suite, byte[] groupId, LeafIndex leafIndex, byte[] encKeyIn, byte[] parentHash, byte[] sigPriv) throws Exception
    {
        LeafNode clone = copy(encKeyIn);
        clone.leaf_node_source = LeafNodeSource.COMMIT;
        clone.parent_hash = parentHash.clone();

        clone.sign(suite, sigPriv, toBeSigned(groupId, leafIndex.value));

        return clone;
    }

    private void sign(CipherSuite suite, byte[] sigPriv, byte[] tbs) throws Exception
    {
        byte[] sigPub = suite.serializeSignaturePublicKey(suite.getSignaturePublicKey(suite.deserializeSignaturePrivateKey(sigPriv)));
        if (!Arrays.equals(sigPub, signature_key))
        {
            throw new Exception("Signature key mismatch");
        }

        //TODO: check if credential is valid for signature key

        signature = suite.signWithLabel(sigPriv, "LeafNodeTBS", tbs);
    }


    //TODO: add options to clone with credential/capabilities/extensions
    private LeafNode copy(byte[] encKeyIn)
    {
        LeafNode clone = new LeafNode();
        clone.encryption_key = encKeyIn.clone();
        clone.signature_key = this.signature_key.clone();
        clone.credential = this.credential;
        clone.capabilities = this.capabilities;
        clone.leaf_node_source =  this.leaf_node_source;
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
        clone.extensions = new ArrayList<>(this.extensions);
        clone.signature = this.signature.clone();
        return clone;
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

