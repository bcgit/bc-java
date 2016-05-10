package com.github.gv2011.bcasn.crypto.params;

import com.github.gv2011.bcasn.crypto.DerivationParameters;

/**
 * parameters for mask derivation functions.
 */
public class MGFParameters
    implements DerivationParameters
{
    byte[]  seed;

    public MGFParameters(
        byte[]  seed)
    {
        this(seed, 0, seed.length);
    }

    public MGFParameters(
        byte[]  seed,
        int     off,
        int     len)
    {
        this.seed = new byte[len];
        System.arraycopy(seed, off, this.seed, 0, len);
    }

    public byte[] getSeed()
    {
        return seed;
    }
}
