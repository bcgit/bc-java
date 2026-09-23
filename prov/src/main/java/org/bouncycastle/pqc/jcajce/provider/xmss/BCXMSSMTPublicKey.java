package org.bouncycastle.pqc.jcajce.provider.xmss;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.XMSSMTPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSMTKey;
import org.bouncycastle.util.Arrays;

/**
 * @deprecated use {@link org.bouncycastle.jcajce.provider.asymmetric.xmss.BCXMSSMTPublicKey} instead.
 */
@Deprecated
public class BCXMSSMTPublicKey
    implements PublicKey, XMSSMTKey
{
    private static final long serialVersionUID = 3230324130542413475L;

    private transient ASN1ObjectIdentifier treeDigest;
    private transient XMSSMTPublicKeyParameters keyParams;

    public BCXMSSMTPublicKey(ASN1ObjectIdentifier treeDigest, XMSSMTPublicKeyParameters keyParams)
    {
        this.treeDigest = treeDigest;
        this.keyParams = keyParams;
    }

    public BCXMSSMTPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.keyParams = (XMSSMTPublicKeyParameters)PublicKeyFactory.createKey(keyInfo);
        this.treeDigest =  DigestUtil.getDigestOID(this.keyParams.getTreeDigest());
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCXMSSMTPublicKey)
        {
            BCXMSSMTPublicKey otherKey = (BCXMSSMTPublicKey)o;

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

    /**
     * @return name of the algorithm - "XMSSMT"
     */
    public final String getAlgorithm()
    {
        return "XMSSMT";
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
        return DigestUtil.getXMSSDigestName(treeDigest, keyParams.getParameters().getTreeDigestSize());
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
