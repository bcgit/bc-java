package org.bouncycastle.pqc.crypto.gemss;

import org.bouncycastle.util.Arrays;

public class GeMSSPrivateKeyParameters
    extends GeMSSKeyParameters
{
    final byte[] sk;
    public GeMSSPrivateKeyParameters(GeMSSParameters parameters,  byte[] skValues)
    {
        super(false, parameters);
        sk = new byte[skValues.length];
        System.arraycopy(skValues, 0, sk, 0, sk.length);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(sk);
    }

}
