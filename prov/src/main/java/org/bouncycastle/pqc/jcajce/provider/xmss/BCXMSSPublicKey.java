package org.bouncycastle.pqc.jcajce.provider.xmss;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSKey;
import org.bouncycastle.util.Arrays;

public class BCXMSSPublicKey
    implements PublicKey, XMSSKey
{
    private static final long serialVersionUID = -5617456225328969766L;
    
    private transient XMSSPublicKeyParameters keyParams;
    private transient ASN1ObjectIdentifier treeDigest;

    public BCXMSSPublicKey(
        ASN1ObjectIdentifier treeDigest,
        XMSSPublicKeyParameters keyParams)
    {
        this.treeDigest = treeDigest;
        this.keyParams = keyParams;
    }

    public BCXMSSPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.keyParams = (XMSSPublicKeyParameters)PublicKeyFactory.createKey(keyInfo);
        this.treeDigest = DigestUtil.getDigestOID(keyParams.getTreeDigest());
    }

    /**
     * @return name of the algorithm - "XMSS"
     */
    public final String getAlgorithm()
    {
        return "XMSS";
    }

    public byte[] getEncoded()
    {
        try
        {
            SubjectPublicKeyInfo pki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyParams);
            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public String getFormat()
    {
        return "X.509";
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

        if (o instanceof BCXMSSPublicKey)
        {
            BCXMSSPublicKey otherKey = (BCXMSSPublicKey)o;

            try
            {
                return treeDigest.equals(otherKey.treeDigest) && Arrays.areEqual(keyParams.getEncoded(), otherKey.keyParams.getEncoded());
            }
            catch (IOException e)
            {
                return false;
            }
        }

        return false;
    }

    public int hashCode()
    {
        try
        {
            return treeDigest.hashCode() + 37 * Arrays.hashCode(keyParams.getEncoded());
        }
        catch (IOException e)
        {
            // should never happen, but...
            return treeDigest.hashCode();
        }
    }

    public int getHeight()
    {
        return keyParams.getParameters().getHeight();
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

        init(SubjectPublicKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
