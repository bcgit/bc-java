package org.bouncycastle.pqc.jcajce.provider.xmss;

import java.security.PrivateKey;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;

public class BCXMSSMTPrivateKey
    implements PrivateKey
{
    private final CipherParameters keyParams;

    public BCXMSSMTPrivateKey(XMSSMTPrivateKeyParameters keyParams)
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

    public CipherParameters getKeyParams()
    {
        return keyParams;
    }
}
