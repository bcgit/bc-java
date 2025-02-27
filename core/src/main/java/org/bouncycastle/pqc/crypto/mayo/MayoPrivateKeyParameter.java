package org.bouncycastle.pqc.crypto.mayo;

import org.bouncycastle.util.Arrays;

public class MayoPrivateKeyParameter
    extends MayoKeyParameters
{
    // Represents the field: uint64_t p[P1_LIMBS_MAX + P2_LIMBS_MAX];
//    private final byte[] p;
    // Represents the field: uint8_t O[V_MAX * O_MAX];
//    private final byte[] O;
    private final byte[] seed_sk;

    public MayoPrivateKeyParameter(MayoParameters params, byte[] seed_sk)
    {
        super(true, params);
        this.seed_sk = seed_sk;
//        this.p = p;
//        this.O = O;
    }

//    public byte[] getP()
//    {
//        return p;
//    }
//
//    public byte[] getO()
//    {
//        return O;
//    }

    public byte[] getEncoded()
    {
        return Arrays.clone(seed_sk);
    }

    public byte[] getSeedSk()
    {
        return Arrays.clone(seed_sk);
    }
}
