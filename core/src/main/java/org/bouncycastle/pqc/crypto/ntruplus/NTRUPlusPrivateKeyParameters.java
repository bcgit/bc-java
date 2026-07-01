package org.bouncycastle.pqc.crypto.ntruplus;

import org.bouncycastle.util.Arrays;

public class NTRUPlusPrivateKeyParameters
    extends NTRUPlusKeyParameters
{
    private final byte[] sk;

    public NTRUPlusPrivateKeyParameters(NTRUPlusParameters params, byte[] sk)
    {
        super(true, params);

        if (sk.length != params.getSecretKeyBytes())
        {
            throw new IllegalArgumentException("'sk' has invalid length");
        }

        this.sk = Arrays.clone(sk);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(sk);
    }
}
