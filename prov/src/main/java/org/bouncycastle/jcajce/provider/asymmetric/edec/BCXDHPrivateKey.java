package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jcajce.interfaces.XDHPrivateKey;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

public class BCXDHPrivateKey
    implements XDHPrivateKey
{
    static final long serialVersionUID = 1L;

    transient AsymmetricKeyParameter xdhPrivateKey;
    transient AsymmetricKeyParameter xdhPublicKey;
    transient int hashCode;

    private final boolean hasPublicKey;
    private final byte[] attributes;

    BCXDHPrivateKey(AsymmetricKeyParameter privKey)
    {
        this.hasPublicKey = true;
        this.attributes = null;
        this.xdhPrivateKey = privKey;
        if (xdhPrivateKey instanceof X448PrivateKeyParameters)
        {
            xdhPublicKey = ((X448PrivateKeyParameters)xdhPrivateKey).generatePublicKey();
        }
        else
        {
            xdhPublicKey = ((X25519PrivateKeyParameters)xdhPrivateKey).generatePublicKey();
        }
        this.hashCode = calculateHashCode();
    }

    BCXDHPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.hasPublicKey = keyInfo.hasPublicKey();
        this.attributes = (keyInfo.getAttributes() != null) ? keyInfo.getAttributes().getEncoded() : null;

        populateFromPrivateKeyInfo(keyInfo);
    }

    private void populateFromPrivateKeyInfo(PrivateKeyInfo keyInfo)
        throws IOException
    {
        int privateKeyLength = keyInfo.getPrivateKeyLength();
        byte[] encoding;

        // exact length of X25519/X448 secret used in Java 11
        if (privateKeyLength == X25519PrivateKeyParameters.KEY_SIZE ||
            privateKeyLength == X448PrivateKeyParameters.KEY_SIZE)
        {
            encoding = keyInfo.getPrivateKey().getOctets();
        }
        else
        {
            encoding = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
        }

        if (EdECObjectIdentifiers.id_X448.equals(keyInfo.getPrivateKeyAlgorithm().getAlgorithm()))
        {
            xdhPrivateKey = new X448PrivateKeyParameters(encoding);
            xdhPublicKey = ((X448PrivateKeyParameters)xdhPrivateKey).generatePublicKey();
        }
        else
        {
            xdhPrivateKey = new X25519PrivateKeyParameters(encoding);
            xdhPublicKey = ((X25519PrivateKeyParameters)xdhPrivateKey).generatePublicKey();
        }

        this.hashCode = calculateHashCode();
    }

    public String getAlgorithm()
    {
        if (Properties.isOverrideSet(Properties.EMULATE_ORACLE))
        {
            return "XDH";
        }

        return (xdhPrivateKey instanceof X448PrivateKeyParameters) ? "X448" : "X25519";
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public byte[] getEncoded()
    {
        try
        {
            PrivateKeyInfo privateKeyInfo = getPrivateKeyInfo();

            if (privateKeyInfo == null)
            {
                return null;
            }

            return privateKeyInfo.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    private PrivateKeyInfo getPrivateKeyInfo()
    {
        try
        {
            ASN1Set attrSet = ASN1Set.getInstance(attributes);
            PrivateKeyInfo privInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(xdhPrivateKey, attrSet);

            if (hasPublicKey && !Properties.isOverrideSet("org.bouncycastle.pkcs8.v1_info_only"))
            {
                return privInfo;
            }
            else
            {
                return new PrivateKeyInfo(privInfo.getPrivateKeyAlgorithm(), privInfo.parsePrivateKey(), attrSet);
            }
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public XDHPublicKey getPublicKey()
    {
        return new BCXDHPublicKey(xdhPublicKey);
    }

    AsymmetricKeyParameter engineGetKeyParameters()
    {
        return xdhPrivateKey;
    }

    public String toString()
    {
        return Utils.keyToString("Private Key", getAlgorithm(), xdhPublicKey);
    }

    public boolean equals(Object o)
    {
        if (o == this)
         {
             return true;
         }

         if (!(o instanceof PrivateKey))
         {
             return false;
         }

         PrivateKey other = (PrivateKey)o;

         PrivateKeyInfo info = this.getPrivateKeyInfo();
         PrivateKeyInfo otherInfo = (other instanceof BCXDHPrivateKey) ? ((BCXDHPrivateKey)other).getPrivateKeyInfo() : PrivateKeyInfo.getInstance(other.getEncoded());

         if (info == null || otherInfo == null)
         {
             return false;
         }

         try
         {
             boolean algEquals = Arrays.constantTimeAreEqual(info.getPrivateKeyAlgorithm().getEncoded(), otherInfo.getPrivateKeyAlgorithm().getEncoded());
             boolean keyEquals = Arrays.constantTimeAreEqual(info.getPrivateKey().getEncoded(), otherInfo.getPrivateKey().getEncoded());

             return algEquals & keyEquals;
         }
         catch (IOException e)
         {
              return false;
         }
    }

    public int hashCode()
    {
        return hashCode;
    }

    private int calculateHashCode()
    {
        byte[] publicData;
        if (xdhPublicKey instanceof X448PublicKeyParameters)
        {
            publicData = ((X448PublicKeyParameters)xdhPublicKey).getEncoded();
        }
        else
        {
            publicData = ((X25519PublicKeyParameters)xdhPublicKey).getEncoded();
        }

        int result = getAlgorithm().hashCode();
        result = 31 * result + Arrays.hashCode(publicData);
        return result;
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        populateFromPrivateKeyInfo(PrivateKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
