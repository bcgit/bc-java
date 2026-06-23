package org.bouncycastle.pqc.crypto.cmce;

import org.bouncycastle.util.Arrays;

public class CMCEPublicKeyParameters
    extends CMCEKeyParameters
{
    private final byte[] publicKey;

    public byte[] getPublicKey()
    {
        return Arrays.clone(publicKey);
    }

    public byte[] getEncoded()
    {
        return getPublicKey();
    }

    public CMCEPublicKeyParameters(CMCEParameters params, byte[] publicKey)
    {
        super(false, params);
        if (publicKey.length != params.getEngine().getPublicKeySize())
        {
            throw new IllegalArgumentException("'encoding' has invalid length");
        }
        this.publicKey = Arrays.clone(publicKey);
    }
}
