package org.bouncycastle.pqc.crypto.smaugt;

import org.bouncycastle.util.Arrays;

/**
 * Lightweight public key parameters for SMAUG-T. Wraps the raw encoded public
 * key bytes produced by {@link SmaugTKeyPairGenerator} for the parameter set
 * carried on the superclass.
 */
public class SmaugTPublicKeyParameters
    extends SmaugTKeyParameters
{
    private final byte[] publicKey;

    public SmaugTPublicKeyParameters(SmaugTParameters params, byte[] publicKey)
    {
        super(false, params);

        if (publicKey.length != params.getEngine().getPublicKeyBytes())
        {
            throw new IllegalArgumentException("'publicKey' has invalid length");
        }

        this.publicKey = Arrays.clone(publicKey);
    }

    public byte[] getPublicKey()
    {
        return Arrays.clone(publicKey);
    }

    public byte[] getEncoded()
    {
        return getPublicKey();
    }
}
