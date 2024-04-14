package org.bouncycastle.mls.codec;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.mls.TreeKEM.LeafIndex;
import org.bouncycastle.mls.TreeKEM.LeafNode;
import org.bouncycastle.mls.TreeKEM.TreeKEMPublicKey;
import org.bouncycastle.mls.crypto.MlsCipherSuite;

public class GroupInfo
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    GroupContext groupContext;
    List<Extension> extensions;
    byte[] confirmationTag;
    LeafIndex signer;
    byte[] signature;

    public byte[] getConfirmationTag()
    {
        return confirmationTag;
    }

    public List<Extension> getExtensions()
    {
        return extensions;
    }

    public LeafIndex getSigner()
    {
        return signer;
    }

    public GroupContext getGroupContext()
    {
        return groupContext;
    }

    public byte[] getGroupID()
    {
        return groupContext.groupID;
    }

    public long getEpoch()
    {
        return groupContext.epoch;
    }

    public MlsCipherSuite getSuite()
    {
        return groupContext.suite;
    }

    public GroupInfo(GroupContext groupContext, List<Extension> extensions, byte[] confirmationTag)
    {
        this.groupContext = groupContext;
        this.extensions = new ArrayList<Extension>(extensions);
        this.confirmationTag = confirmationTag;
    }

    private byte[] toBeSigned()
        throws IOException
    {
        MLSOutputStream stream = new MLSOutputStream();
        stream.write(groupContext);
        stream.writeList(extensions);
        stream.writeOpaque(confirmationTag);
        stream.write(signer);
        return stream.toByteArray();
    }

    public boolean verify(MlsCipherSuite suite, TreeKEMPublicKey tree)
        throws Exception
    {
        LeafNode leaf = tree.getLeafNode(signer);
        if (leaf == null)
        {
            throw new Exception("Signer not found");
        }
        return verify(suite, leaf.getSignatureKey());
    }

    public boolean verify(MlsCipherSuite suite, byte[] pub)
        throws IOException
    {
        return suite.verifyWithLabel(pub, "GroupInfoTBS", toBeSigned(), signature);
    }

    @SuppressWarnings("unused")
    GroupInfo(MLSInputStream stream)
        throws IOException
    {
        groupContext = (GroupContext)stream.read(GroupContext.class);
        extensions = new ArrayList<Extension>();
        stream.readList(extensions, Extension.class);
        confirmationTag = stream.readOpaque();
        signer = new LeafIndex((int)stream.read(int.class));
        signature = stream.readOpaque();
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.write(groupContext);
        stream.writeList(extensions);
        stream.writeOpaque(confirmationTag);
        stream.write(signer);
        stream.writeOpaque(signature);
    }

    public void sign(TreeKEMPublicKey tree, LeafIndex signerIndex, AsymmetricCipherKeyPair sk)
        throws Exception
    {
        LeafNode leaf = tree.getLeafNode(signerIndex);
        if (leaf == null)
        {
            throw new Exception("Cannot sign from a blank leaf");
        }

        if (!Arrays.equals(tree.getSuite().serializeSignaturePublicKey(sk.getPublic()), leaf.getSignatureKey()))
        {
            throw new Exception("Bad key for index");
        }

        signer = signerIndex;
        signature = tree.getSuite().signWithLabel(tree.getSuite().serializeSignaturePrivateKey(sk.getPrivate()), "GroupInfoTBS", toBeSigned());
    }
}