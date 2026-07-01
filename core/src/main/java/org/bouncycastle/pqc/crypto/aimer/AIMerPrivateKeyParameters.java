package org.bouncycastle.pqc.crypto.aimer;

import org.bouncycastle.util.Arrays;

/**
 * Lightweight private key parameters for AIMer. Wraps the raw encoded private
 * key bytes produced by {@link AIMerKeyPairGenerator} for the parameter set
 * carried on the superclass.
 */
public class AIMerPrivateKeyParameters
    extends AIMerKeyParameters
{
    private final byte[] keyData;

    public AIMerPrivateKeyParameters(AIMerParameters params, byte[] keyData)
    {
        super(true, params);
        this.keyData = Arrays.clone(keyData);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(keyData);
    }
}