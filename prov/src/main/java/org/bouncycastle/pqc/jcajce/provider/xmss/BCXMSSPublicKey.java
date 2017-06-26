package org.bouncycastle.pqc.jcajce.provider.xmss;

import java.security.PublicKey;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters;

public class BCXMSSPublicKey
    implements PublicKey
{
    private final CipherParameters keyParams;

    public BCXMSSPublicKey(XMSSPublicKeyParameters keyParams)
    {
        this.keyParams = keyParams;
    }

    /**
     * @return name of the algorithm - "XMSS"
     */
    public final String getAlgorithm()
    {
        return "XMSS";
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
