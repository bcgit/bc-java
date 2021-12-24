package org.bouncycastle.pqc.crypto.cmce;

import org.bouncycastle.util.Arrays;

public class CMCEPrivateKeyParameters
    extends CMCEKeyParameters
{

    private byte[] privateKey;

    public void setPrivateKey(byte[] privateKey)
    {
        this.privateKey = privateKey;
    }

    public byte[] getPrivateKey()
    {
        return privateKey;
    }

    public CMCEPrivateKeyParameters(byte[] privateKey, CMCEParameters params)
    {
        super(true, params);
        this.privateKey = Arrays.clone(privateKey);
    }
}
