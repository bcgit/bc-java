package org.bouncycastle.pqc.crypto.cmce;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

public class CMCEPublicKeyParameters
    extends CMCEKeyParameters
{


    public byte[] getPublicKey()
    {
        return publicKey;
    }

    private byte[] publicKey;
    public CMCEPublicKeyParameters(byte[] publicKey, CMCEParameters params)
    {
        super(false, params);
        this.publicKey = Arrays.clone(publicKey);
    }
}
