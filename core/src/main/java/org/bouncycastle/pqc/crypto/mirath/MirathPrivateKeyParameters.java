package org.bouncycastle.pqc.crypto.mirath;

import org.bouncycastle.util.Arrays;

public class MirathPrivateKeyParameters
    extends MirathKeyParameters
{
    private final byte[] seed;

    public MirathPrivateKeyParameters(MirathParameters params, byte[] seed)
    {
        super(true, params);
        this.seed = Arrays.clone(seed);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(seed);
    }
}
