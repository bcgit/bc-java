package org.bouncycastle.pqc.crypto.mayo;

import org.bouncycastle.util.Arrays;

public class MayoPrivateKeyParameters
    extends MayoKeyParameters
{
    private final byte[] seed_sk;

    public MayoPrivateKeyParameters(MayoParameters params, byte[] seed_sk)
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
