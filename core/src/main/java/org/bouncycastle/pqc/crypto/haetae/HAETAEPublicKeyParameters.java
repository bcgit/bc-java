package org.bouncycastle.pqc.crypto.haetae;

import org.bouncycastle.util.Arrays;

public class HAETAEPublicKeyParameters
    extends HAETAEKeyParameters
{
    private final byte[] p;

    public HAETAEPublicKeyParameters(HAETAEParameters params, byte[] p)
    {
        super(false, params);
        this.p = Arrays.clone(p);
    }

    public byte[] getP()
    {
        return Arrays.clone(p);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(p);
    }
}
