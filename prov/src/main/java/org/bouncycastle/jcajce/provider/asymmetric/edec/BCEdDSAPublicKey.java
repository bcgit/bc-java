package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.security.PublicKey;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.interfaces.EdDSAKey;

public class BCEdDSAPublicKey
    implements EdDSAKey, PublicKey
{
    private transient AsymmetricKeyParameter eddsaPublicKey;

    BCEdDSAPublicKey(SubjectPublicKeyInfo keyInfo)
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
        try
        {
            return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(eddsaPublicKey).getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    AsymmetricKeyParameter engineGetKeyParameters()
    {
        return eddsaPublicKey;
    }
}
