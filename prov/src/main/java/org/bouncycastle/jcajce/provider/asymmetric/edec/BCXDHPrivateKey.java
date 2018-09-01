package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jcajce.interfaces.XDHKey;

public class BCXDHPrivateKey
    implements XDHKey, PrivateKey
{
    private transient AsymmetricKeyParameter xdhPrivateKey;

    private final boolean hasPublicKey;
    private final byte[] attributes;

    BCXDHPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.hasPublicKey = keyInfo.hasPublicKey();
        this.attributes = (keyInfo.getAttributes() != null) ? keyInfo.getAttributes().getEncoded() : null;

        ASN1Encodable keyOcts = keyInfo.parsePrivateKey();
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
            PrivateKeyInfo privInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(xdhPrivateKey, ASN1Set.getInstance(attributes));

            if (hasPublicKey)
            {
                return privInfo.getEncoded();
            }
            else
            {
                return new PrivateKeyInfo(privInfo.getPrivateKeyAlgorithm(), privInfo.parsePrivateKey(), ASN1Set.getInstance(attributes)).getEncoded();
            }
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public AlgorithmParameterSpec getParams()
    {
        return null;
    }
}
