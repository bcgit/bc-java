package org.bouncycastle.pqc.crypto.mirath;

import org.bouncycastle.util.Arrays;

public class MirathPublicKeyParameters
    extends MirathKeyParameters
{
    private final byte[] p;

    public MirathPublicKeyParameters(MirathParameters params, byte[] p)
    {
        super(false, params);
        this.p = Arrays.clone(p);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(p);
    }
}