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
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
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

    private final boolean hasPublicKey;
    private final byte[] attributes;

    BCXDHPrivateKey(AsymmetricKeyParameter privKey)
    {
        this.hasPublicKey = true;
        this.attributes = null;
        this.xdhPrivateKey = privKey;
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
        ASN1OctetString keyOcts = keyInfo.getPrivateKey();
        byte[] infoOcts = keyOcts.getOctets();

        if (infoOcts.length != 32 && infoOcts.length != 56) // exact length of X25519/X448 secret used in Java 11
        {
            keyOcts = ASN1OctetString.getInstance(keyInfo.parsePrivateKey());
        }

        if (EdECObjectIdentifiers.id_X448.equals(keyInfo.getPrivateKeyAlgorithm().getAlgorithm()))
        {
            xdhPrivateKey = new X448PrivateKeyParameters(ASN1OctetString.getInstance(keyOcts).getOctets(), 0);
        }
        else
        {
            xdhPrivateKey = new X25519PrivateKeyParameters(ASN1OctetString.getInstance(keyOcts).getOctets(), 0);
        }
    }

    public String getAlgorithm()
    {
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
            ASN1Set attrSet = ASN1Set.getInstance(attributes);
            PrivateKeyInfo privInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(xdhPrivateKey, attrSet);

            if (hasPublicKey && !Properties.isOverrideSet("org.bouncycastle.pkcs8.v1_info_only"))
            {
                return privInfo.getEncoded();
            }
            else
            {
                return new PrivateKeyInfo(privInfo.getPrivateKeyAlgorithm(), privInfo.parsePrivateKey(), attrSet).getEncoded();
            }
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public XDHPublicKey getPublicKey()
    {
        if (xdhPrivateKey instanceof X448PrivateKeyParameters)
        {
            return new BCXDHPublicKey(((X448PrivateKeyParameters)xdhPrivateKey).generatePublicKey());
        }
        else
        {
            return new BCXDHPublicKey(((X25519PrivateKeyParameters)xdhPrivateKey).generatePublicKey());
        }
    }

    AsymmetricKeyParameter engineGetKeyParameters()
    {
        return xdhPrivateKey;
    }

    public String toString()
    {
        AsymmetricKeyParameter pubKey;
        if (xdhPrivateKey instanceof X448PrivateKeyParameters)
        {
            pubKey = ((X448PrivateKeyParameters)xdhPrivateKey).generatePublicKey();
        }
        else
        {
            pubKey = ((X25519PrivateKeyParameters)xdhPrivateKey).generatePublicKey();
        }
        return Utils.keyToString("Private Key", getAlgorithm(), pubKey);
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

        return Arrays.areEqual(other.getEncoded(), this.getEncoded());
    }

    public int hashCode()
    {
        return Arrays.hashCode(this.getEncoded());
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
