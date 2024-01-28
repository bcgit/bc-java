package org.bouncycastle.mls.codec;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.mls.TreeKEM.TreeKEMPublicKey;

public class Extension
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    public ExtensionType extensionType;
    public byte[] extension_data;

    public Extension(ExtensionType extensionType, byte[] extension_data)
    {
        this.extensionType = extensionType;
        this.extension_data = extension_data;
    }

    public Extension(int extensionType, byte[] extension_data)
    {
        short extType = (short)extensionType;
        if (Grease.isGrease(extType) == -1)
        {
            this.extensionType = ExtensionType.values()[extType];
        }
        else
        {
            this.extensionType = ExtensionType.values()[6 + Grease.isGrease(extType)];
        }
        this.extension_data = extension_data;
    }

    static public Extension externalSender(List<ExternalSender> list)
        throws IOException
    {
        MLSOutputStream stream = new MLSOutputStream();
        stream.writeList(list);
        return new Extension(ExtensionType.EXTERNAL_SENDERS, stream.toByteArray());
    }

    public byte[] getExternalPub()
        throws IOException
    {
        if (extensionType == ExtensionType.EXTERNAL_PUB)
        {
            MLSInputStream stream = new MLSInputStream(extension_data);
            byte[] output = stream.readOpaque();
            return output;
        }
        return null;
    }

    @SuppressWarnings("unused")
    Extension(MLSInputStream stream)
        throws IOException
    {
        short extType = (short)stream.read(short.class);
        if (Grease.isGrease(extType) == -1)
        {
            this.extensionType = ExtensionType.values()[extType];
        }
        else
        {
            this.extensionType = ExtensionType.values()[6 + Grease.isGrease(extType)];
        }
        this.extension_data = stream.readOpaque();
    }

    public List<ExternalSender> getSenders()
        throws IOException
    {
        if (extensionType == ExtensionType.EXTERNAL_SENDERS)
        {
            List<ExternalSender> senders = new ArrayList<ExternalSender>();
            MLSInputStream stream = new MLSInputStream(extension_data);
            stream.readList(senders, ExternalSender.class);
            return senders;
        }
        return null;
    }

    public TreeKEMPublicKey getRatchetTree()
        throws IOException
    {
        if (extensionType == ExtensionType.RATCHET_TREE)
        {
            return (TreeKEMPublicKey)MLSInputStream.decode(extension_data, TreeKEMPublicKey.class);
        }
        return null;
    }


    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.write(extensionType);
        stream.writeOpaque(extension_data);
    }
}
