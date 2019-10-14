package org.bouncycastle.pqc.jcajce.provider.xmss;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.asn1.XMSSMTKeyParams;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSMTPrivateKey;
import org.bouncycastle.util.Arrays;

public class BCXMSSMTPrivateKey
    implements PrivateKey, XMSSMTPrivateKey
{
    private static final long serialVersionUID = 7682140473044521395L;

    private transient ASN1ObjectIdentifier treeDigest;
    private transient XMSSMTPrivateKeyParameters keyParams;
    private transient ASN1Set attributes;

    public BCXMSSMTPrivateKey(
        ASN1ObjectIdentifier treeDigest,
        XMSSMTPrivateKeyParameters keyParams)
    {
        this.treeDigest = treeDigest;
        this.keyParams = keyParams;
    }

    public BCXMSSMTPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        XMSSMTKeyParams keyParams = XMSSMTKeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters());
        this.treeDigest = keyParams.getTreeDigest().getAlgorithm();
        this.keyParams = (XMSSMTPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
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

    public XMSSMTPrivateKey extractKeyShard(int usageCount)
    {
        return new BCXMSSMTPrivateKey(this.treeDigest, keyParams.extractKeyShard(usageCount));
    }

    public String getAlgorithm()
    {
        return "XMSSMT";
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

    CipherParameters getKeyParams()
    {
        return keyParams;
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCXMSSMTPrivateKey)
        {
            BCXMSSMTPrivateKey otherKey = (BCXMSSMTPrivateKey)o;

            return treeDigest.equals(otherKey.treeDigest) && Arrays.areEqual(keyParams.toByteArray(), otherKey.keyParams.toByteArray());
        }

        return false;
    }

    public int hashCode()
    {
        return treeDigest.hashCode() + 37 * Arrays.hashCode(keyParams.toByteArray());
    }

    ASN1ObjectIdentifier getTreeDigestOID()
    {
        return treeDigest;
    }

    public int getHeight()
    {
        return keyParams.getParameters().getHeight();
    }

    public int getLayers()
    {
        return keyParams.getParameters().getLayers();
    }

    public String getTreeDigest()
    {
        return DigestUtil.getXMSSDigestName(treeDigest);
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
