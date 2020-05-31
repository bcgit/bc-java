package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.util.Arrays;

public class BCEdDSAPublicKey
    implements EdDSAPublicKey
{
    static final long serialVersionUID = 1L;

    transient AsymmetricKeyParameter eddsaPublicKey;

    BCEdDSAPublicKey(AsymmetricKeyParameter pubKey)
    {
        this.eddsaPublicKey = pubKey;
    }

    BCEdDSAPublicKey(SubjectPublicKeyInfo keyInfo)
    {
        populateFromPubKeyInfo(keyInfo);
    }

    BCEdDSAPublicKey(byte[] prefix, byte[] rawData)
        throws InvalidKeySpecException
    {
        int prefixLength = prefix.length;

        if (Utils.isValidPrefix(prefix, rawData))
        {
            if ((rawData.length - prefixLength) == Ed448PublicKeyParameters.KEY_SIZE)
            {
                eddsaPublicKey = new Ed448PublicKeyParameters(rawData, prefixLength);
            }
            else if ((rawData.length - prefixLength) == Ed25519PublicKeyParameters.KEY_SIZE)
            {
                eddsaPublicKey = new Ed25519PublicKeyParameters(rawData, prefixLength);
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
        if (EdECObjectIdentifiers.id_Ed448.equals(keyInfo.getAlgorithm().getAlgorithm()))
        {
            eddsaPublicKey = new Ed448PublicKeyParameters(keyInfo.getPublicKeyData().getOctets(), 0);
        }
        else
        {
            eddsaPublicKey = new Ed25519PublicKeyParameters(keyInfo.getPublicKeyData().getOctets(), 0);
        }
    }

    public String getAlgorithm()
    {
        return (eddsaPublicKey instanceof Ed448PublicKeyParameters) ? "Ed448" : "Ed25519";
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getEncoded()
    {
        if (eddsaPublicKey instanceof Ed448PublicKeyParameters)
        {
            byte[] encoding = new byte[KeyFactorySpi.Ed448Prefix.length + Ed448PublicKeyParameters.KEY_SIZE];

            System.arraycopy(KeyFactorySpi.Ed448Prefix, 0, encoding, 0, KeyFactorySpi.Ed448Prefix.length);

            ((Ed448PublicKeyParameters)eddsaPublicKey).encode(encoding, KeyFactorySpi.Ed448Prefix.length);

            return encoding;
        }
        else
        {
            byte[] encoding = new byte[KeyFactorySpi.Ed25519Prefix.length + Ed25519PublicKeyParameters.KEY_SIZE];

            System.arraycopy(KeyFactorySpi.Ed25519Prefix, 0, encoding, 0, KeyFactorySpi.Ed25519Prefix.length);

            ((Ed25519PublicKeyParameters)eddsaPublicKey).encode(encoding, KeyFactorySpi.Ed25519Prefix.length);

            return encoding;
        }
    }

    AsymmetricKeyParameter engineGetKeyParameters()
    {
        return eddsaPublicKey;
    }

    public String toString()
    {
        return Utils.keyToString("Public Key", getAlgorithm(), eddsaPublicKey);
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
