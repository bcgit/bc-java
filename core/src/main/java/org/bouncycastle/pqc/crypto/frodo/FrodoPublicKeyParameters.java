package org.bouncycastle.pqc.crypto.frodo;

import org.bouncycastle.util.Arrays;

public class FrodoPublicKeyParameters
    extends FrodoKeyParameters
{

    public byte[] publicKey;

    public byte[] getPublicKey()
    {
        return publicKey;
    }

    public FrodoPublicKeyParameters(byte[] publicKey, FrodoParameters params)
    {
        super(false, params);
        this.publicKey = Arrays.clone(publicKey);
    }
}
