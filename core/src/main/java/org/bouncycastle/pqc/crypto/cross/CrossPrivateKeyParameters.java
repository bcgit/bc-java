package org.bouncycastle.pqc.crypto.cross;

import org.bouncycastle.util.Arrays;

public class CrossPrivateKeyParameters
    extends CrossKeyParameters
{
    private final byte[] seed_sk;

    public CrossPrivateKeyParameters(CrossParameters params, byte[] seed_sk)
    {
        super(true, params);
        this.seed_sk = Arrays.clone(seed_sk);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(seed_sk);
    }
}
