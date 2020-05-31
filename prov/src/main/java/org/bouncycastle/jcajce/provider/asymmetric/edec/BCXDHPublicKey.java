package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;
import org.bouncycastle.util.Arrays;

public class BCXDHPublicKey
    implements XDHPublicKey
{
    static final long serialVersionUID = 1L;

    transient AsymmetricKeyParameter xdhPublicKey;

    BCXDHPublicKey(AsymmetricKeyParameter pubKey)
    {
        this.xdhPublicKey = pubKey;
    }

    BCXDHPublicKey(SubjectPublicKeyInfo keyInfo)
    {
        populateFromPubKeyInfo(keyInfo);
    }

    BCXDHPublicKey(byte[] prefix, byte[] rawData)
        throws InvalidKeySpecException
    {
        int prefixLength = prefix.length;

        if (Utils.isValidPrefix(prefix, rawData))
        {
            if ((rawData.length - prefixLength) == X448PublicKeyParameters.KEY_SIZE)
            {
                xdhPublicKey = new X448PublicKeyParameters(rawData, prefixLength);
            }
            else if ((rawData.length - prefixLength) == X25519PublicKeyParameters.KEY_SIZE)
            {
                xdhPublicKey = new X25519PublicKeyParameters(rawData, prefixLength);
            }
            else
            {
                throw new InvalidKeySpecException("raw key data not recognised");
            }
        }
        else
        {
            throw new InvalidKeySpecException("raw key data not recognised");
        }
    }

    private void populateFromPubKeyInfo(SubjectPublicKeyInfo keyInfo)
    {
        if (EdECObjectIdentifiers.id_X448.equals(keyInfo.getAlgorithm().getAlgorithm()))
        {
            xdhPublicKey = new X448PublicKeyParameters(keyInfo.getPublicKeyData().getOctets(), 0);
        }
        else
        {
            xdhPublicKey = new X25519PublicKeyParameters(keyInfo.getPublicKeyData().getOctets(), 0);
        }
    }

    public String getAlgorithm()
    {
        return (xdhPublicKey instanceof X448PublicKeyParameters) ? "X448" : "X25519";
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getEncoded()
    {
        if (xdhPublicKey instanceof X448PublicKeyParameters)
        {
            byte[] encoding = new byte[KeyFactorySpi.x448Prefix.length + X448PublicKeyParameters.KEY_SIZE];

            System.arraycopy(KeyFactorySpi.x448Prefix, 0, encoding, 0, KeyFactorySpi.x448Prefix.length);

            ((X448PublicKeyParameters)xdhPublicKey).encode(encoding, KeyFactorySpi.x448Prefix.length);

            return encoding;
        }
        else
        {
            byte[] encoding = new byte[KeyFactorySpi.x25519Prefix.length + X25519PublicKeyParameters.KEY_SIZE];

            System.arraycopy(KeyFactorySpi.x25519Prefix, 0, encoding, 0, KeyFactorySpi.x25519Prefix.length);

            ((X25519PublicKeyParameters)xdhPublicKey).encode(encoding, KeyFactorySpi.x25519Prefix.length);

            return encoding;
        }
    }

    AsymmetricKeyParameter engineGetKeyParameters()
    {
        return xdhPublicKey;
    }

    public String toString()
    {
        return Utils.keyToString("Public Key", getAlgorithm(), xdhPublicKey);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof PublicKey))
        {
            return false;
        }

        PublicKey other = (PublicKey)o;

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

        populateFromPubKeyInfo(SubjectPublicKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
