package org.bouncycastle.pqc.crypto.smaugt;

import org.bouncycastle.util.Arrays;

/**
 * Lightweight private key parameters for SMAUG-T. Wraps the raw encoded
 * private key bytes produced by {@link SmaugTKeyPairGenerator} for the
 * parameter set carried on the superclass.
 */
public class SmaugTPrivateKeyParameters
    extends SmaugTKeyParameters
{
    private final byte[] privateKey;

    public SmaugTPrivateKeyParameters(SmaugTParameters params, byte[] privateKey)
    {
        super(true, params);

        if (privateKey.length != params.getEngine().getKemSecretKeyBytes())
        {
            throw new IllegalArgumentException("'privateKey' has invalid length");
        }

        this.privateKey = Arrays.clone(privateKey);
    }

    public byte[] getPrivateKey()
    {
        return Arrays.clone(privateKey);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(privateKey);
    }
}
