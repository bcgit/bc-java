package org.bouncycastle.pqc.jcajce.provider.xmss;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSPrivateKey;
import org.bouncycastle.util.Arrays;

public class BCXMSSPrivateKey
    implements PrivateKey, XMSSPrivateKey
{
    private static final long serialVersionUID = 8568701712864512338L;

    private transient XMSSPrivateKeyParameters keyParams;
    private transient ASN1ObjectIdentifier treeDigest;
    private transient ASN1Set attributes;

    public BCXMSSPrivateKey(
        ASN1ObjectIdentifier treeDigest,
        XMSSPrivateKeyParameters keyParams)
    {
        this.treeDigest = treeDigest;
        this.keyParams = keyParams;
    }

    public BCXMSSPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        // Derive the tree digest from the recovered key rather than the AlgorithmIdentifier
        // parameters: the RFC 9802 form (id-alg-xmss-hashsig) carries no XMSSKeyParams, so reading
        // them would NPE. Mirrors BCXMSSPublicKey.init.
        this.keyParams = (XMSSPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
        this.treeDigest = DigestUtil.getDigestOID(keyParams.getTreeDigest());
    }

    public long getIndex()
    {
        if (getUsagesRemaining() == 0)
        {
            throw new IllegalStateException("key exhausted");
        }
        return keyParams.getIndex();
    }

    public long getUsagesRemaining()
    {
        return keyParams.getUsagesRemaining();
    }

    public XMSSPrivateKey extractKeyShard(int usageCount)
    {
        return new BCXMSSPrivateKey(this.treeDigest, keyParams.extractKeyShard(usageCount));
    }

    public String getAlgorithm()
    {
        return "XMSS";
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public byte[] getEncoded()
    {
        try
        {
            PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo(keyParams, attributes);

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCXMSSPrivateKey)
        {
            BCXMSSPrivateKey otherKey = (BCXMSSPrivateKey)o;

            return treeDigest.equals(otherKey.treeDigest) & Arrays.constantTimeAreEqual(keyParams.toByteArray(), otherKey.keyParams.toByteArray());
        }

        return false;
    }

    public int hashCode()
    {
        return getPublicKey().hashCode();
    }

    private BCXMSSPublicKey getPublicKey()
    {
        XMSSPublicKeyParameters pubParams = new XMSSPublicKeyParameters.Builder(keyParams.getParameters())
            .withRoot(keyParams.getRoot())
            .withPublicSeed(keyParams.getPublicSeed())
            .build();
        return new BCXMSSPublicKey(treeDigest, pubParams);
    }

    CipherParameters getKeyParams()
    {
        return keyParams;
    }

    ASN1ObjectIdentifier getTreeDigestOID()
    {
        return treeDigest;
    }

    public int getHeight()
    {
        return keyParams.getParameters().getHeight();
    }

    public String getTreeDigest()
    {
        return DigestUtil.getXMSSDigestName(treeDigest, keyParams.getParameters().getTreeDigestSize());
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        init(PrivateKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
