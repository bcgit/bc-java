package org.bouncycastle.pqc.crypto.frodo;

import org.bouncycastle.util.Arrays;

public class FrodoPrivateKeyParameters
    extends FrodoKeyParameters
{
    private byte[] privateKey;

    public byte[] getPrivateKey()
    {
        return Arrays.clone(privateKey);
    }

    public FrodoPrivateKeyParameters(FrodoParameters params, byte[] privateKey)
    {
        super(true, params);
        this.privateKey = Arrays.clone(privateKey);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(privateKey);
    }
}
