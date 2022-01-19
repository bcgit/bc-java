package org.bouncycastle.pqc.crypto.cmce;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.Arrays;

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
    public byte[] reconstructPublicKey()
    {
        CMCEEngine engine = getParameters().getEngine();
        byte[] pk = new byte[engine.getPublicKeySize()];
        engine.generate_public_key_from_private_key(privateKey);
        return pk;
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(privateKey);
    }

    public byte[] getDelta()
    {
        return ByteUtils.subArray(privateKey,0, 32);
    }

    public byte[] getC()
    {
        return ByteUtils.subArray(privateKey, 32, 32+8);
    }

    public byte[] getG()
    {
        return ByteUtils.subArray(privateKey, 40, 40+getParameters().getT()*2);
    }

    public byte[] getAlpha()
    {
        return ByteUtils.subArray(privateKey, 40+getParameters().getT()*2, privateKey.length-32);
    }

    public byte[] getS()
    {
        return ByteUtils.subArray(privateKey, privateKey.length-32, privateKey.length);
    }
}
