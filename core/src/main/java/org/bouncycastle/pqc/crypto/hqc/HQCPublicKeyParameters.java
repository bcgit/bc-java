package org.bouncycastle.pqc.crypto.hqc;

import org.bouncycastle.util.Arrays;

public class HQCPublicKeyParameters
    extends HQCKeyParameters
{
    private final byte[] pk;

    public HQCPublicKeyParameters(HQCParameters params, byte[] pk)
    {
        super(true, params);

        if (pk.length != params.getPublicKeyBytes())
        {
            throw new IllegalArgumentException("'pk' has invalid length");
        }

        this.pk = Arrays.clone(pk);
    }

    public byte[] getPublicKey()
    {
        return Arrays.clone(pk);
    }

    public byte[] getEncoded()
    {
        return getPublicKey();
    }
}
