package org.bouncycastle.pqc.crypto.haetae;

import org.bouncycastle.util.Arrays;

/**
 * Lightweight private key parameters for HAETAE. Wraps the raw encoded private
 * key bytes (the secret seed) produced by {@link HAETAEKeyPairGenerator} for
 * the parameter set carried on the superclass.
 */
public class HAETAEPrivateKeyParameters
    extends HAETAEKeyParameters
{
    private final byte[] seed_sk;

    public HAETAEPrivateKeyParameters(HAETAEParameters params, byte[] seed_sk)
    {
        super(true, params);

        if (seed_sk.length != params.getSecretKeyBytes())
        {
            throw new IllegalArgumentException("'seed_sk' has invalid length");
        }

        this.seed_sk = Arrays.clone(seed_sk);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(seed_sk);
    }

    public byte[] getSeedSk()
    {
        return Arrays.clone(seed_sk);
    }
}
