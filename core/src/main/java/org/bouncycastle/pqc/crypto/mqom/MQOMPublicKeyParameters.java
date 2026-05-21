package org.bouncycastle.pqc.crypto.mqom;

import org.bouncycastle.util.Arrays;

public class MQOMPublicKeyParameters
    extends MQOMKeyParameters
{
    private final byte[] encoded;

    public MQOMPublicKeyParameters(MQOMParameters params, byte[] encoded)
    {
        super(false, params);
        if (encoded == null)
        {
            throw new NullPointerException("encoded cannot be null");
        }
        if (encoded.length != params.getPublicKeySize())
        {
            throw new IllegalArgumentException("public key length wrong for " + params.getName()
                + ": expected " + params.getPublicKeySize() + " bytes, got " + encoded.length);
        }
        this.encoded = Arrays.clone(encoded);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(encoded);
    }

    public byte[] getMSeedEq()
    {
        return Arrays.copyOfRange(encoded, 0, 2 * getParameters().getSeedSize());
    }

    public byte[] getY()
    {
        MQOMParameters p = getParameters();
        int off = 2 * p.getSeedSize();
        return Arrays.copyOfRange(encoded, off, encoded.length);
    }
}
