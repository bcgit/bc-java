package org.bouncycastle.pqc.crypto.ntruplus;

import org.bouncycastle.util.Arrays;

public class NTRUPlusPublicKeyParameters
    extends NTRUPlusKeyParameters
{
    private final byte[] p;

    public NTRUPlusPublicKeyParameters(NTRUPlusParameters params, byte[] p)
    {
        super(false, params);

        if (p.length != params.getPublicKeyBytes())
        {
            throw new IllegalArgumentException("'p' has invalid length");
        }

        this.p = Arrays.clone(p);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(p);
    }
}