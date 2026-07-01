package org.bouncycastle.crypto.params;

import org.bouncycastle.util.Arrays;

public class CMCEPublicKeyParameters
    extends CMCEKeyParameters
{
    final byte[] publicKey;

    public CMCEPublicKeyParameters(CMCEParameters params, byte[] publicKey)
    {
        super(false, params);
        this.publicKey = Arrays.clone(publicKey);
    }

    public byte[] getPublicKey()
    {
        return Arrays.clone(publicKey);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(publicKey);
    }
}
