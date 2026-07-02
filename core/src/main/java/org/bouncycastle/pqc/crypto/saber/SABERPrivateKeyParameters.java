package org.bouncycastle.pqc.crypto.saber;

import org.bouncycastle.util.Arrays;

public class SABERPrivateKeyParameters
    extends SABERKeyParameters
{
    private byte[] privateKey;

    public SABERPrivateKeyParameters(SABERParameters params, byte[] privateKey)
    {
        super(true, params);

        if (privateKey.length != params.getEngine().getPrivateKeySize())
        {
            throw new IllegalArgumentException("'privateKey' has invalid length");
        }

        this.privateKey = Arrays.clone(privateKey);
    }

    public byte[] getPrivateKey()
    {
        return Arrays.clone(privateKey);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(privateKey);
    }
}
