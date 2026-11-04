package org.bouncycastle.pqc.legacy.bike;

import org.bouncycastle.util.Arrays;

public class BIKEPublicKeyParameters
    extends BIKEKeyParameters
{
    byte[] publicKey;

    /**
     * Constructor.
     *
     * @param publicKey byte
     */
    public BIKEPublicKeyParameters(BIKEParameters params, byte[] publicKey)
    {
        super(false, params);
        if (publicKey.length != params.getRByte())
        {
            throw new IllegalArgumentException("'publicKey' has invalid length");
        }
        this.publicKey = Arrays.clone(publicKey);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(publicKey);
    }
}
