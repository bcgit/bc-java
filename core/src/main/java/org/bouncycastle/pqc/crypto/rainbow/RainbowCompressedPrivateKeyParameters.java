package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.util.Arrays;

public class RainbowCompressedPrivateKeyParameters
    extends RainbowKeyParameters
{
    private byte[] sk_seed;
    private byte[] pk_seed;

    public RainbowCompressedPrivateKeyParameters(RainbowParameters params, byte[] sk_seed, byte[] pk_seed)
    {
        super(true, params);
        this.sk_seed = sk_seed.clone();
        this.pk_seed = pk_seed.clone();
    }

    public byte[] getSk_seed()
    {
        return Arrays.clone(sk_seed);
    }

    public byte[] getPk_seed()
    {
        return Arrays.clone(pk_seed);
    }

    public byte[] getEncoded()
    {
        return Arrays.concatenate(getPk_seed(), getSk_seed());
    }
}
