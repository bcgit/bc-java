package org.bouncycastle.pqc.crypto.falcon;

import org.bouncycastle.util.Arrays;

public class FalconPrivateKeyParameters
    extends FalconKeyParameters
{

    private final byte[] sk;
    private final byte[] pk;

    public FalconPrivateKeyParameters(FalconParameters parameters, byte[] sk_encoded, byte[] pk_encoded)
    {
        super(true, parameters);
        this.sk = Arrays.clone(sk_encoded);
        this.pk = Arrays.clone(pk_encoded);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(sk);
    }

    public byte[] getPublicKey()
    {
        return Arrays.clone(pk);
    }
}
