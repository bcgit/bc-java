package org.bouncycastle.pqc.crypto.ntruprime;

import org.bouncycastle.util.Arrays;

public class NTRULPRimePublicKeyParameters
    extends NTRULPRimeKeyParameters
{
    private final byte[] seed;
    private final byte[] roundEncA;

    public NTRULPRimePublicKeyParameters(NTRULPRimeParameters params, byte[] encoding)
    {
        super(false, params);
        this.seed = Arrays.copyOfRange(encoding, 0, 32);
        this.roundEncA = Arrays.copyOfRange(encoding, seed.length, encoding.length);
    }

    NTRULPRimePublicKeyParameters(NTRULPRimeParameters params, byte[] seed, byte[] roundEncA)
    {
        super(false, params);
        this.seed = Arrays.clone(seed);
        this.roundEncA = Arrays.clone(roundEncA);
    }

    byte[] getSeed()
    {
        return seed;
    }

    byte[] getRoundEncA()
    {
        return roundEncA;
    }

    public byte[] getEncoded()
    {
        byte[] key = new byte[getParameters().getPublicKeyBytes()];
        System.arraycopy(seed, 0, key, 0, seed.length);
        System.arraycopy(roundEncA, 0, key, seed.length, roundEncA.length);
        return key;
    }
}
