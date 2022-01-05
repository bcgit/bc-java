package org.bouncycastle.pqc.crypto.cmce;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class CMCEPrivateKeyParameters
    extends CMCEKeyParameters
{

    private final byte[] privateKey;

    public byte[] getPrivateKey()
    {
        return Arrays.clone(privateKey);
    }

    public CMCEPrivateKeyParameters(CMCEParameters params, byte[] privateKey)
    {
        super(true, params);
        this.privateKey = Arrays.clone(privateKey);
    }

    public byte[] getEncoded()
    {
        return Arrays.concatenate(Pack.longToBigEndian(CMCEParameters.getID(getParameters())), privateKey);
    }
}
