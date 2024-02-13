package org.bouncycastle.mls.codec;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.mls.TreeKEM.LeafNode;
import org.bouncycastle.mls.TreeKEM.LeafNodeSource;
import org.bouncycastle.mls.crypto.MlsCipherSuite;

public class KeyPackage
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    ProtocolVersion version;

    MlsCipherSuite suite;
    short cipher_suite;
    byte[] init_key;
    LeafNode leaf_node;
    List<Extension> extensions;
    /* SignWithLabel(., "KeyPackageTBS", KeyPackageTBS) */
    byte[] signature; // KeyPackageTBS (without signature)

    public LeafNode getLeafNode()
    {
        return leaf_node;
    }

    public byte[] getInitKey()
    {
        return init_key;
    }

    public MlsCipherSuite getSuite()
    {
        return suite;
    }

    public boolean verify()
        throws IOException
    {
        // Verify the inner leaf node
        if (!leaf_node.verify(suite, leaf_node.toBeSigned(new byte[0], -1)))
        {
            return false;
        }

        // Check that the inner leaf node is intended for use in a KeyPackage
        if (leaf_node.getSource() != LeafNodeSource.KEY_PACKAGE)
        {
            return false;
        }

        // Verify the KeyPackage
        if (leaf_node.getCredentialType() == CredentialType.x509)
        {
            //TODO: check if credential scheme is actually x509
            // and the credential scheme doesn't equal to the tls signature scheme (given the signature id)
        }

        return suite.verifyWithLabel(leaf_node.getSignatureKey(), "KeyPackageTBS", toBeSigned(), signature);
    }

    private byte[] toBeSigned()
        throws IOException
    {
        MLSOutputStream stream = new MLSOutputStream();
        stream.write(version);
        stream.write(cipher_suite);
        stream.writeOpaque(init_key);
        stream.write(leaf_node);
        stream.writeList(extensions);
        return stream.toByteArray();
    }

    public KeyPackage(MlsCipherSuite suite, byte[] init_key, LeafNode leaf_node, List<Extension> extensions, byte[] sigSk)
        throws IOException, CryptoException
    {
        this.version = ProtocolVersion.mls10;
        this.cipher_suite = suite.getSuiteID();
        this.suite = suite;
        this.init_key = init_key.clone();
        this.leaf_node = leaf_node.copy(leaf_node.getEncryptionKey());
        this.extensions = new ArrayList<Extension>(extensions);

        //sign(sigSk)
        this.signature = suite.signWithLabel(sigSk, "KeyPackageTBS", toBeSigned());
    }

    @SuppressWarnings("unused")
    KeyPackage(MLSInputStream stream)
        throws Exception
    {
        this.version = ProtocolVersion.values()[(short)stream.read(short.class)];
        cipher_suite = (short)stream.read(short.class);
        suite = MlsCipherSuite.getSuite(cipher_suite);
        init_key = stream.readOpaque();
        leaf_node = (LeafNode)stream.read(LeafNode.class);
        extensions = new ArrayList<Extension>();
        stream.readList(extensions, Extension.class);
        signature = stream.readOpaque();
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.write(version);
        stream.write(cipher_suite);
        stream.writeOpaque(init_key);
        stream.write(leaf_node);
        stream.writeList(extensions);
        stream.writeOpaque(signature);
    }
}
