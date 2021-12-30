package org.bouncycastle.pqc.crypto.cmce;

import org.bouncycastle.util.Arrays;

public class CMCEPrivateKeyParameters
    extends CMCEKeyParameters
{

    private byte[] privateKey;

    public byte[] getPrivateKey()
    {
        return Arrays.clone(privateKey);
    }

    public CMCEPrivateKeyParameters(byte[] privateKey, CMCEParameters params)
    {
        super(true, params);
        this.privateKey = Arrays.clone(privateKey);
    }
}
