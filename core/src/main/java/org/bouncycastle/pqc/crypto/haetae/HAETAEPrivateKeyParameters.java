package org.bouncycastle.pqc.crypto.haetae;

import org.bouncycastle.util.Arrays;

public class HAETAEPrivateKeyParameters
    extends HAETAEKeyParameters
{
    private final byte[] seed_sk;

    public HAETAEPrivateKeyParameters(HAETAEParameters params, byte[] seed_sk)
    {
        super(true, params);
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
