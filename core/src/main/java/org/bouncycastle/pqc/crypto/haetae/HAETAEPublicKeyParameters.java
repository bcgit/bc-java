package org.bouncycastle.pqc.crypto.haetae;

import org.bouncycastle.util.Arrays;

/**
 * Lightweight public key parameters for HAETAE. Wraps the raw encoded public
 * key bytes produced by {@link HAETAEKeyPairGenerator} for the parameter set
 * carried on the superclass.
 */
public class HAETAEPublicKeyParameters
    extends HAETAEKeyParameters
{
    private final byte[] p;

    public HAETAEPublicKeyParameters(HAETAEParameters params, byte[] p)
    {
        super(false, params);

        if (p.length != params.getPublicKeyBytes())
        {
            throw new IllegalArgumentException("'p' has invalid length");
        }

        this.p = Arrays.clone(p);
    }

    public byte[] getP()
    {
        return Arrays.clone(p);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(p);
    }
}
