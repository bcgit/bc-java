package org.bouncycastle.pqc.crypto.mayo;

import org.bouncycastle.util.Arrays;

public class MayoPublicKeyParameter
    extends MayoKeyParameters
{
    // Represents the field: uint64_t p[P1_LIMBS_MAX + P2_LIMBS_MAX + P3_LIMBS_MAX];
    private final byte[] p;

    public MayoPublicKeyParameter(MayoParameters params, byte[] p)
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
