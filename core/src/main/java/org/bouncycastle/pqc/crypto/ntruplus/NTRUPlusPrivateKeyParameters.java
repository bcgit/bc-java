package org.bouncycastle.pqc.crypto.ntruplus;

import org.bouncycastle.util.Arrays;

public class NTRUPlusPrivateKeyParameters
    extends NTRUPlusKeyParameters
{
    private final byte[] seed_sk;

    public NTRUPlusPrivateKeyParameters(NTRUPlusParameters params, byte[] seed_sk)
    {
        super(true, params);
        this.seed_sk = Arrays.clone(seed_sk);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(seed_sk);
    }
}
