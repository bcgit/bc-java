package org.bouncycastle.pqc.jcajce.provider.xmss;

import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;

public class BCXMSSMTPrivateKey
    implements PrivateKey
{
    private final XMSSMTPrivateKeyParameters keyParams;

    public BCXMSSMTPrivateKey(
        ASN1ObjectIdentifier treeDigest,
        XMSSMTPrivateKeyParameters keyParams)
    {
        this.keyParams = keyParams;
    }

    public String getAlgorithm()
    {
        return "XMSSMT";
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public byte[] getEncoded()
    {
        return new byte[0];
    }

    CipherParameters getKeyParams()
    {
        return keyParams;
    }
}
