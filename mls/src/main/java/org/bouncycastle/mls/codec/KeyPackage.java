package org.bouncycastle.mls.codec;

import org.bouncycastle.mls.TreeKEM.LeafNode;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class KeyPackage
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    ProtocolVersion version;
    public short cipher_suite;
    byte[] init_key;
    LeafNode leaf_node;
    List<Extension> extensions;
    /* SignWithLabel(., "KeyPackageTBS", KeyPackageTBS) */
    byte[] signature; // KeyPackageTBS (without signature)

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
