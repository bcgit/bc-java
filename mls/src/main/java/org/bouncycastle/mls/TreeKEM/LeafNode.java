package org.bouncycastle.mls.TreeKEM;

import org.bouncycastle.mls.client.Group;
import org.bouncycastle.mls.codec.Capabilities;
import org.bouncycastle.mls.codec.Credential;
import org.bouncycastle.mls.codec.CredentialType;
import org.bouncycastle.mls.codec.Extension;
import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoField;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class LeafNode
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    CipherSuite suite;
    public byte[] encryption_key;
    public byte[] signature_key;
    Credential credential;
    public Capabilities capabilities;
    LeafNodeSource leaf_node_source;

    //in switch
    LifeTime lifeTime;
    byte[] parent_hash;

    public List<Extension> extensions;
    /* SignWithLabel(., "LeafNodeTBS", LeafNodeTBS) */
    public byte[] signature; // not in TBS

    public CredentialType getCredentialType()
    {
        return credential.credentialType;
    }

    public CipherSuite getSuite()
    {
        return suite;
    }

    public LifeTime getLifeTime()
    {
        return lifeTime;
    }

    public LeafNode(
            CipherSuite suite,
            byte[] encryption_key,
            byte[] signature_key,
            Credential credential,
            Capabilities capabilities,
            LifeTime lifeTime,
            List<Extension> extensions,
            byte[] sigSk) throws Exception
    {
        this.suite = suite;
        this.encryption_key = encryption_key;
        this.signature_key = signature_key;
        this.credential = credential;
        this.capabilities = capabilities; //TODO: grease
        this.lifeTime = lifeTime;
        this.extensions = new ArrayList<>(extensions); //TODO: grease
        this.leaf_node_source = LeafNodeSource.KEY_PACKAGE; //TODO: check

        sign(suite, sigSk, toBeSigned(null, -1));
    }

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

    public LeafNodeSource getSource()
    {
        return leaf_node_source;
    }

    public Credential getCredential()
    {
        return credential;
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

    public boolean verifyExtensionSupport(List<Extension> extensions)
    {
        //TODO: Verify that extensions in the list are supported

        //TODO: Verify Required Capability extension is supported (if there is one)

        return true;
    }

    public boolean verifyLifetime()
    {
        //TODO: check
        if (leaf_node_source != LeafNodeSource.KEY_PACKAGE)
        {
            return true;
        }
        long now = Instant.now().getLong(ChronoField.INSTANT_SECONDS);
        if (lifeTime.not_after == -1)
        {
            return (now >= lifeTime.not_before) && (now < Long.MAX_VALUE);
        }
        return (now >= lifeTime.not_before) && (now < lifeTime.not_after);
    }

    public boolean verify(CipherSuite suite, byte[] tbs) throws IOException
    {
//        System.out.println("tbs: " + Hex.toHexString(tbs));
//        System.out.println("sig: " + Hex.toHexString(signature));
//        System.out.println("sigkey: " + Hex.toHexString(signature_key));
        if (getCredentialType() == CredentialType.x509)
        {
            //TODO: get credential and check if it's signature scheme matches the cipher suite signature scheme
        }

        return suite.verifyWithLabel(signature_key, "LeafNodeTBS", tbs, signature);
    }

    public LeafNode forCommit(CipherSuite suite, byte[] groupId, LeafIndex leafIndex, byte[] encKeyIn, byte[] parentHash, Group.LeafNodeOptions options, byte[] sigPriv) throws Exception
    {
        LeafNode clone = copyWithOptions(encKeyIn, options);
        clone.leaf_node_source = LeafNodeSource.COMMIT;
        clone.parent_hash = parentHash.clone();

        clone.sign(suite, sigPriv, clone.toBeSigned(groupId, leafIndex.value));

        return clone;
    }
    public LeafNode forUpdate(CipherSuite suite, byte[] groupId, LeafIndex leafIndex, byte[] encKeyIn, Group.LeafNodeOptions options, byte[] sigPriv) throws Exception
    {
        LeafNode clone = copyWithOptions(encKeyIn, options);
        clone.leaf_node_source = LeafNodeSource.UPDATE;

        clone.sign(suite, sigPriv, clone.toBeSigned(groupId, leafIndex.value));

        return clone;
    }

    private void sign(CipherSuite suite, byte[] sigPriv, byte[] tbs) throws Exception
    {
        System.out.println("tbs: " + Hex.toHexString(tbs));
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

        LeafNode leafNode = (LeafNode) o;

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

