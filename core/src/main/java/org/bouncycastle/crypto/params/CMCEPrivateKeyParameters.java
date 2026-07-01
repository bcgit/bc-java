package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.kems.cmce.CMCEEngine;
import org.bouncycastle.util.Arrays;

public class CMCEPrivateKeyParameters
    extends CMCEKeyParameters
{
    final byte[] privateKey;

    public CMCEPrivateKeyParameters(CMCEParameters params, byte[] privateKey)
    {
        super(true, params);

        if (privateKey.length != CMCEEngine.getInstance(params).getPrivateKeySize())
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
