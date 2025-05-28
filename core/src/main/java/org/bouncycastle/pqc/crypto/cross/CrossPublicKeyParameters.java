package org.bouncycastle.pqc.crypto.cross;

import org.bouncycastle.util.Arrays;

public class CrossPublicKeyParameters
    extends CrossKeyParameters
{
    private final byte[] p;

    public CrossPublicKeyParameters(CrossParameters params, byte[] p)
    {
        super(false, params);
        this.p = Arrays.clone(p);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(p);
    }
}
