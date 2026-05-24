package org.bouncycastle.pqc.crypto.hawk;

import org.bouncycastle.util.Arrays;

/**
 * Lightweight private key parameters for Hawk. Wraps the raw encoded private
 * key bytes produced by {@link HawkKeyPairGenerator} for the parameter set
 * carried on the superclass.
 */
public class HawkPrivateKeyParameters
    extends HawkKeyParameters
{
    private final byte[] priv;

    public HawkPrivateKeyParameters(HawkParameters params, byte[] input, int inOff, int len)
    {
        super(true, params);
        this.priv = Arrays.copyOfRange(input, inOff, inOff + len);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(priv);
    }
}
