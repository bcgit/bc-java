package org.bouncycastle.pqc.crypto.frodo;

import org.bouncycastle.util.Arrays;

public class FrodoPrivateKeyParameters
    extends FrodoKeyParameters
{
    private byte[] privateKey;

    public byte[] getPrivateKey()
    {
        return privateKey;
    }

    public void setPrivateKey(byte[] privateKey)
    {
        this.privateKey = privateKey;
    }

    public FrodoPrivateKeyParameters(byte[] privateKey, FrodoParameters params)
    {
        super(true, params);
        this.privateKey = Arrays.clone(privateKey);
    }
}
