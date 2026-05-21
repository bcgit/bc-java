package org.bouncycastle.pqc.crypto.mqom;

import org.bouncycastle.util.Arrays;

public class MQOMPrivateKeyParameters
    extends MQOMKeyParameters
{
    private final byte[] encoded;

    public MQOMPrivateKeyParameters(MQOMParameters params, byte[] encoded)
    {
        super(true, params);
        if (encoded == null)
        {
            throw new NullPointerException("encoded cannot be null");
        }
        if (encoded.length != params.getPrivateKeySize())
        {
            throw new IllegalArgumentException("private key length wrong for " + params.getName()
                + ": expected " + params.getPrivateKeySize() + " bytes, got " + encoded.length);
        }
        this.encoded = Arrays.clone(encoded);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(encoded);
    }

    public byte[] getPublicKey()
    {
        return Arrays.copyOfRange(encoded, 0, getParameters().getPublicKeySize());
    }

    public byte[] getX()
    {
        MQOMParameters p = getParameters();
        int off = p.getPublicKeySize();
        return Arrays.copyOfRange(encoded, off, encoded.length);
    }

    public MQOMPublicKeyParameters getPublicKeyParameters()
    {
        return new MQOMPublicKeyParameters(getParameters(), getPublicKey());
    }
}
