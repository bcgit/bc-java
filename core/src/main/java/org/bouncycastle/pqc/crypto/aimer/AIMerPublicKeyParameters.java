package org.bouncycastle.pqc.crypto.aimer;

import org.bouncycastle.util.Arrays;

/**
 * Lightweight public key parameters for AIMer. Wraps the raw encoded public
 * key bytes produced by {@link AIMerKeyPairGenerator} for the parameter set
 * carried on the superclass.
 */
public class AIMerPublicKeyParameters
    extends AIMerKeyParameters
{
    private final byte[] keyData;

    public AIMerPublicKeyParameters(AIMerParameters params, byte[] keyData)
    {
        super(false, params); // public key
        if (keyData.length != params.getPublicKeyBytes())
        {
            throw new IllegalArgumentException("'keyData' has invalid length");
        }
        this.keyData = Arrays.clone(keyData);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(keyData);
    }
}