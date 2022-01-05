package org.bouncycastle.pqc.crypto.cmce;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class CMCEPublicKeyParameters
    extends CMCEKeyParameters
{
    private final byte[] publicKey;

    public byte[] getPublicKey()
    {
        return Arrays.clone(publicKey);
    }

    public byte[] getEncoded()
    {
        return Arrays.concatenate(Pack.longToBigEndian(CMCEParameters.getID(getParameters())), publicKey);
    }

    public CMCEPublicKeyParameters(CMCEParameters params, byte[] publicKey)
    {
        super(false, params);
        this.publicKey = Arrays.clone(publicKey);
    }
}
