package org.bouncycastle.crypto.params;

import org.bouncycastle.util.Arrays;

public class FrodoKEMPublicKeyParameters
    extends FrodoKEMKeyParameters
{
    final byte[] publicKey;

    public FrodoKEMPublicKeyParameters(FrodoKEMParameters params, byte[] publicKey)
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
