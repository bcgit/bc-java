package org.bouncycastle.mls.codec;

import org.bouncycastle.mls.TreeKEM.TreeKEMPublicKey;

import java.io.IOException;

public class Extension
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    public ExtensionType extensionType;
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

    public TreeKEMPublicKey getRatchetTree() throws IOException
    {
        if (extensionType == ExtensionType.RATCHET_TREE)
        {
            return (TreeKEMPublicKey) MLSInputStream.decode(extension_data, TreeKEMPublicKey.class);
        }
        return null;
    }


    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(extensionType);
        stream.writeOpaque(extension_data);
    }
}
