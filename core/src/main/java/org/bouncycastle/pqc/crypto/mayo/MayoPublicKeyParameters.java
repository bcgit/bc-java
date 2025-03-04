package org.bouncycastle.pqc.crypto.mayo;

import org.bouncycastle.util.Arrays;

public class MayoPublicKeyParameters
    extends MayoKeyParameters
{
    private final byte[] p;

    public MayoPublicKeyParameters(MayoParameters params, byte[] p)
    {
        super(false, params);
        this.p = p;
    }

    public byte[] getP()
    {
        return p;
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(p);
    }
}
