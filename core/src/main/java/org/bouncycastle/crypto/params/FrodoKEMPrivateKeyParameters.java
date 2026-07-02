package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.kems.frodo.FrodoKEMEngine;
import org.bouncycastle.util.Arrays;

public class FrodoKEMPrivateKeyParameters
    extends FrodoKEMKeyParameters
{
    final byte[] privateKey;

    public FrodoKEMPrivateKeyParameters(FrodoKEMParameters params, byte[] privateKey)
    {
        super(true, params);

        if (privateKey.length != FrodoKEMEngine.getInstance(params).getPrivateKeySize())
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
