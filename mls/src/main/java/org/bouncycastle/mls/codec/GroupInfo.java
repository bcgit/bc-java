package org.bouncycastle.mls.codec;

import org.bouncycastle.mls.crypto.CipherSuite;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class GroupInfo
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    public GroupContext groupContext;
    List<Extension> extensions;
    public byte[] confirmationTag;
    int signer;
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
        signer = (int) stream.read(int.class);
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

//TODO: replaced with toBeSigned()
//class GroupInfoTBS
//        implements MLSInputStream.Readable, MLSOutputStream.Writable
//{
//    GroupContext groupContext;
//    List<Extension> extensions;
//    byte[] confirmationTag;
//    int signer;
//
//    public GroupInfoTBS(GroupContext groupContext, List<Extension> extensions, byte[] confirmationTag, int signer)
//    {
//        this.groupContext = groupContext;
//        this.extensions = extensions;
//        this.confirmationTag = confirmationTag;
//        this.signer = signer;
//    }
//
//    GroupInfoTBS(MLSInputStream stream) throws IOException
//    {
//        groupContext = (GroupContext) stream.read(GroupContext.class);
//        extensions = new ArrayList<>();
//        stream.readList(extensions, Extension.class);
//        confirmationTag = stream.readOpaque();
//        signer = (int) stream.read(int.class);
//    }
//
//    @Override
//    public void writeTo(MLSOutputStream stream) throws IOException
//    {
//        stream.write(groupContext);
//        stream.writeList(extensions);
//        stream.writeOpaque(confirmationTag);
//        stream.write(signer);
//    }
//}
