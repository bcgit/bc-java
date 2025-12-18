package org.bouncycastle.pqc.crypto.ntruplus;

import org.bouncycastle.util.Arrays;

public class NTRUPlusPrivateKeyParameters
    extends NTRUPlusKeyParameters
{
    private final byte[] sk;

    public NTRUPlusPrivateKeyParameters(NTRUPlusParameters params, byte[] sk)
    {
        super(true, params);
        this.sk = Arrays.clone(sk);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(sk);
    }
}
