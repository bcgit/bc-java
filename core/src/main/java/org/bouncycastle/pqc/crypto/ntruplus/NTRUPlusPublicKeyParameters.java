package org.bouncycastle.pqc.crypto.ntruplus;

import org.bouncycastle.util.Arrays;

public class NTRUPlusPublicKeyParameters
    extends NTRUPlusKeyParameters
{
    private final byte[] p;

    public NTRUPlusPublicKeyParameters(NTRUPlusParameters params, byte[] p)
    {
        super(false, params);
        this.p = Arrays.clone(p);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(p);
    }
}