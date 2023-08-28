package org.bouncycastle.mls.codec;

import org.bouncycastle.mls.TreeKEM.LeafIndex;
import org.bouncycastle.mls.TreeKEM.LeafNode;
import org.bouncycastle.mls.TreeKEM.TreeKEMPublicKey;
import org.bouncycastle.mls.crypto.CipherSuite;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class GroupInfo
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    //TODO: replace suite with groupContext.suite
    public GroupContext groupContext;
    public List<Extension> extensions;
    public byte[] confirmationTag;
    public LeafIndex signer;
    byte[] signature;

    private byte[] toBeSigned() throws IOException
    {
        MLSOutputStream stream = new MLSOutputStream();
        stream.write(groupContext);
        stream.writeList(extensions);
        stream.writeOpaque(confirmationTag);
        stream.write(signer);
        return stream.toByteArray();
    }

    public boolean verify(CipherSuite suite, TreeKEMPublicKey tree) throws Exception
    {
        LeafNode leaf = tree.getLeafNode(signer);
        if (leaf == null)
        {
            throw new Exception("Signer not found");
        }
        return verify(suite, leaf.signature_key);
    }
    public boolean verify(CipherSuite suite, byte[] pub) throws IOException
    {
        return suite.verifyWithLabel(pub, "GroupInfoTBS", toBeSigned(), signature);
    }

    GroupInfo(MLSInputStream stream) throws IOException
    {
        groupContext = (GroupContext) stream.read(GroupContext.class);
        extensions = new ArrayList<>();
        stream.readList(extensions, Extension.class);
        confirmationTag = stream.readOpaque();
        signer = new LeafIndex((int) stream.read(int.class));
        signature = stream.readOpaque();
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(groupContext);
        stream.writeList(extensions);
        stream.writeOpaque(confirmationTag);
        stream.write(signer);
        stream.writeOpaque(signature);
    }
}