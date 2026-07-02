package org.bouncycastle.pqc.crypto.hawk;

import org.bouncycastle.util.Arrays;

/**
 * Lightweight public key parameters for Hawk. Wraps the raw encoded public key
 * bytes produced by {@link HawkKeyPairGenerator} for the parameter set carried
 * on the superclass.
 */
public class HawkPublicKeyParameters
    extends HawkKeyParameters
{
    private final byte[] pub;

    public HawkPublicKeyParameters(HawkParameters params, byte[] input, int inOff, int len)
    {
        super(false, params);

        if (len != params.getPublicKeySize())
        {
            throw new IllegalArgumentException("'len' does not match public key size");
        }

        this.pub = Arrays.copyOfRange(input, inOff, inOff + len);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(pub);
    }
}
