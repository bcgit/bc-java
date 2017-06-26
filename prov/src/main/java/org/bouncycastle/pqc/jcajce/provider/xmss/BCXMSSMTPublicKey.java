package org.bouncycastle.pqc.jcajce.provider.xmss;

import java.security.PublicKey;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKeyParameters;

public class BCXMSSMTPublicKey
    implements PublicKey
{
    private final CipherParameters keyParams;

    public BCXMSSMTPublicKey(XMSSMTPublicKeyParameters keyParams)
    {
        this.keyParams = keyParams;
    }

    /**
     * Compare this XMSSMT public key with another object.
     *
     * @param o the other object
     * @return the result of the comparison
     */
    public boolean equals(Object o)
    {
        if (o == null || !(o instanceof BCXMSSMTPublicKey))
        {
            return false;
        }
        BCXMSSMTPublicKey otherKey = (BCXMSSMTPublicKey)o;

        return false; //treeDigest.equals(otherKey.treeDigest) && Arrays.areEqual(params.getKeyData(), otherKey.params.getKeyData());
    }

//    public int hashCode()
//    {
//        return treeDigest.hashCode() + 37 * Arrays.hashCode(params.getKeyData());
//    }

    /**
     * @return name of the algorithm - "XMSSMT"
     */
    public final String getAlgorithm()
    {
        return "XMSSMT";
    }

    public byte[] getEncoded()
    {
        SubjectPublicKeyInfo pki;

        return null;
    }

    public String getFormat()
    {
        return "X.509";
    }

    CipherParameters getKeyParams()
    {
        return keyParams;
    }
}
