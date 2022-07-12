package org.bouncycastle.pqc.crypto.falcon;

import org.bouncycastle.util.Arrays;

public class FalconPrivateKeyParameters
    extends FalconKeyParameters
{

    private byte[] sk;

    public FalconPrivateKeyParameters(FalconParameters parameters, byte[] sk_encoded)
    {
        super(true, parameters);
        this.sk = Arrays.clone(sk_encoded);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(sk);
    }
}
