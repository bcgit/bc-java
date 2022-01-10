package org.bouncycastle.pqc.crypto.frodo;

import org.bouncycastle.util.Arrays;

public class FrodoPublicKeyParameters
    extends FrodoKeyParameters
{

    public byte[] publicKey;

    public byte[] getPublicKey()
    {
        return Arrays.clone(publicKey);
    }

    public byte[] getEncoded()
    {
        return getPublicKey();
    }

    public FrodoPublicKeyParameters(FrodoParameters params, byte[] publicKey)
    {
        super(false, params);
        this.publicKey = Arrays.clone(publicKey);
    }
}
