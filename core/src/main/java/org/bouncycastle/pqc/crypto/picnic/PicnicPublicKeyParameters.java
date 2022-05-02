package org.bouncycastle.pqc.crypto.picnic;

import org.bouncycastle.util.Arrays;

public class PicnicPublicKeyParameters
    extends PicnicKeyParameters
{

    private  final byte[] publicKey;

//    public picnicPublicKeyParameters(picnicParameters parameters, byte[] ptEncoded, byte[] ctEncoded)
    public PicnicPublicKeyParameters(PicnicParameters parameters, byte[] pkEncoded)
    {
        super(false, parameters);
        publicKey = Arrays.clone(pkEncoded);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(publicKey);
    }

}
