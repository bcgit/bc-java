package org.bouncycastle.pqc.crypto.cmce;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

import java.lang.reflect.Array;

public class CMCEPrivateKeyParameters
        extends CMCEKeyParameters
{

    private byte[] privateKey;

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
