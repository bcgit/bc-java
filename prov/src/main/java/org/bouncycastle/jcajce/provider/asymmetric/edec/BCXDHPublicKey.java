package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.security.PublicKey;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.interfaces.XDHKey;

public class BCXDHPublicKey
    implements XDHKey, PublicKey
{
    private transient AsymmetricKeyParameter xdhPublicKey;

    BCXDHPublicKey(AsymmetricKeyParameter pubKey)
    {
        this.xdhPublicKey = pubKey;
    }

    BCXDHPublicKey(SubjectPublicKeyInfo keyInfo)
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
        try
        {
            return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(xdhPublicKey).getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    AsymmetricKeyParameter engineGetKeyParameters()
    {
        return xdhPublicKey;
    }
}
