package org.bouncycastle.mls.codec;

import org.bouncycastle.mls.TreeKEM.LeafNode;
import org.bouncycastle.mls.TreeKEM.LeafNodeSource;
import org.bouncycastle.mls.crypto.CipherSuite;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class KeyPackage
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    ProtocolVersion version;
    public short cipher_suite;
    public byte[] init_key;
    public LeafNode leaf_node;
    List<Extension> extensions;
    /* SignWithLabel(., "KeyPackageTBS", KeyPackageTBS) */
    byte[] signature; // KeyPackageTBS (without signature)

    public boolean verify() throws IOException
    {
        CipherSuite suite = new CipherSuite(cipher_suite);
        // Verify the inner leaf node
        if (!leaf_node.verify(suite, leaf_node.toBeSigned(null, -1)))
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

        return suite.verifyWithLabel(leaf_node.signature_key, "KeyPackageTBS", toBeSigned(), signature);
    }

    private byte[] toBeSigned() throws IOException
    {
        MLSOutputStream stream = new MLSOutputStream();
        stream.write(version);
        stream.write(cipher_suite);
        stream.writeOpaque(init_key);
        stream.write(leaf_node);
        stream.writeList(extensions);
        return stream.toByteArray();
    }

    KeyPackage(MLSInputStream stream) throws IOException
    {
        this.version = ProtocolVersion.values()[(short) stream.read(short.class)];
        cipher_suite = (short) stream.read(short.class);
        init_key = stream.readOpaque();
        leaf_node = (LeafNode) stream.read(LeafNode.class);
        extensions = new ArrayList<>();
        stream.readList(extensions, Extension.class);
        signature = stream.readOpaque();
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(version);
        stream.write(cipher_suite);
        stream.writeOpaque(init_key);
        stream.write(leaf_node);
        stream.writeList(extensions);
        stream.writeOpaque(signature);
    }
}
