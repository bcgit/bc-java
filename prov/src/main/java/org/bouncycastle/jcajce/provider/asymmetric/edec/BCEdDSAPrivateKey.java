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
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

public class BCEdDSAPrivateKey
    implements EdDSAPrivateKey
{
    static final long serialVersionUID = 1L;
    
    transient AsymmetricKeyParameter eddsaPrivateKey;
    transient AsymmetricKeyParameter eddsaPublicKey;
    transient int hashCode;

    private final boolean hasPublicKey;
    private final byte[] attributes;

    BCEdDSAPrivateKey(AsymmetricKeyParameter privKey)
    {
        this.hasPublicKey = true;
        this.attributes = null;
        this.eddsaPrivateKey = privKey;
        if (eddsaPrivateKey instanceof Ed448PrivateKeyParameters)
        {
            eddsaPublicKey = ((Ed448PrivateKeyParameters)eddsaPrivateKey).generatePublicKey();
        }
        else
        {
            eddsaPublicKey = ((Ed25519PrivateKeyParameters)eddsaPrivateKey).generatePublicKey();
        }
        this.hashCode = calculateHashCode();
    }

    BCEdDSAPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.hasPublicKey = keyInfo.hasPublicKey();
        this.attributes = (keyInfo.getAttributes() != null) ? keyInfo.getAttributes().getEncoded() : null;

        populateFromPrivateKeyInfo(keyInfo);
    }

    private void populateFromPrivateKeyInfo(PrivateKeyInfo keyInfo)
        throws IOException
    {
        byte[] encoding = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();

        if (EdECObjectIdentifiers.id_Ed448.equals(keyInfo.getPrivateKeyAlgorithm().getAlgorithm()))
        {
            eddsaPrivateKey = new Ed448PrivateKeyParameters(encoding);
            eddsaPublicKey = ((Ed448PrivateKeyParameters)eddsaPrivateKey).generatePublicKey();
        }
        else
        {
            eddsaPrivateKey = new Ed25519PrivateKeyParameters(encoding);
            eddsaPublicKey = ((Ed25519PrivateKeyParameters)eddsaPrivateKey).generatePublicKey();
        }

        this.hashCode = calculateHashCode();
    }

    public String getAlgorithm()
    {
        if (Properties.isOverrideSet(Properties.EMULATE_ORACLE))
        {
            return "EdDSA";
        }

        return (eddsaPrivateKey instanceof Ed448PrivateKeyParameters) ? "Ed448" : "Ed25519";
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public byte[] getEncoded()
    {
        try
        {
            PrivateKeyInfo keyInfo = getPrivateKeyInfo();
            if (keyInfo == null)
            {
                return null;
            }

            return keyInfo.getEncoded();
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
            PrivateKeyInfo privInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(eddsaPrivateKey, attrSet);

            if (hasPublicKey && !Properties.isOverrideSet("org.bouncycastle.pkcs8.v1_info_only"))
            {
                return privInfo;
            }

            return new PrivateKeyInfo(privInfo.getPrivateKeyAlgorithm(), privInfo.parsePrivateKey(), attrSet);
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public EdDSAPublicKey getPublicKey()
    {
        return new BCEdDSAPublicKey(eddsaPublicKey);
    }

    AsymmetricKeyParameter engineGetKeyParameters()
    {
        return eddsaPrivateKey;
    }

    public String toString()
    {
        return Utils.keyToString("Private Key", getAlgorithm(), eddsaPublicKey);
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
        PrivateKeyInfo otherInfo = (other instanceof BCEdDSAPrivateKey) ? ((BCEdDSAPrivateKey)other).getPrivateKeyInfo() : PrivateKeyInfo.getInstance(other.getEncoded());

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
        if (eddsaPublicKey instanceof Ed448PublicKeyParameters)
        {
            publicData = ((Ed448PublicKeyParameters)eddsaPublicKey).getEncoded();
        }
        else
        {
            publicData = ((Ed25519PublicKeyParameters)eddsaPublicKey).getEncoded();
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
