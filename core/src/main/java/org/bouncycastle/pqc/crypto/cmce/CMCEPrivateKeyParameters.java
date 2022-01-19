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
    public CMCEPrivateKeyParameters(CMCEParameters params, byte[] delta, byte[] C, byte[] g, byte[] alpha, byte[] s)
    {

        super(true, params);
        int sk_size = delta.length + C.length + g.length + alpha.length + s.length;
        privateKey = new byte[sk_size];
        int offset = 0;
        System.arraycopy(privateKey, offset, delta, 0, delta.length);
        offset += delta.length;
        System.arraycopy(privateKey, offset, C, 0, C.length);
        offset += C.length;
        System.arraycopy(privateKey, offset, g, 0, g.length);
        offset += g.length;
        System.arraycopy(privateKey, offset, alpha, 0, alpha.length);
        offset += alpha.length;
        System.arraycopy(privateKey, offset, s, 0, s.length);

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
