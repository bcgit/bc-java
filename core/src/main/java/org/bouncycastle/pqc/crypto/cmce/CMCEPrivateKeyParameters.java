package org.bouncycastle.pqc.crypto.cmce;

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
        System.arraycopy(delta, 0, privateKey, offset, delta.length);
        offset += delta.length;
        System.arraycopy(C, 0, privateKey, offset, C.length);
        offset += C.length;
        System.arraycopy(g, 0, privateKey, offset, g.length);
        offset += g.length;
        System.arraycopy(alpha, 0, privateKey, offset, alpha.length);
        offset += alpha.length;
        System.arraycopy(s, 0, privateKey, offset, s.length);

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
        return Arrays.copyOfRange(privateKey,0, 32);
    }

    public byte[] getC()
    {
        return Arrays.copyOfRange(privateKey, 32, 32+8);
    }

    public byte[] getG()
    {
        return Arrays.copyOfRange(privateKey, 40, 40+getParameters().getT()*2);
    }

    public byte[] getAlpha()
    {
        return Arrays.copyOfRange(privateKey, 40+getParameters().getT()*2, privateKey.length-32);
    }

    public byte[] getS()
    {
        return Arrays.copyOfRange(privateKey, privateKey.length-32, privateKey.length);
    }
}
