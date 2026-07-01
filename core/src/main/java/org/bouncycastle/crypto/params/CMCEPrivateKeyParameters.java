package org.bouncycastle.crypto.params;

import org.bouncycastle.util.Arrays;

public class CMCEPrivateKeyParameters
    extends CMCEKeyParameters
{
    final byte[] privateKey;

    public CMCEPrivateKeyParameters(CMCEParameters params, byte[] privateKey)
    {
        super(true, params);
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
