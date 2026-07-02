package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.kems.frodo.FrodoKEMEngine;
import org.bouncycastle.util.Arrays;

public class FrodoKEMPublicKeyParameters
    extends FrodoKEMKeyParameters
{
    final byte[] publicKey;

    public FrodoKEMPublicKeyParameters(FrodoKEMParameters params, byte[] publicKey)
    {
        super(false, params);

        if (publicKey.length != FrodoKEMEngine.getInstance(params).getPublicKeySize())
        {
            throw new IllegalArgumentException("'publicKey' has invalid length");
        }

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
