package org.bouncycastle.pqc.crypto.crystals.kyber;

import org.bouncycastle.util.Arrays;

public class KyberPublicKeyParameters
    extends KyberKeyParameters
{
    final byte[] t;
    final byte[] rho;

    public byte[] getPublicKey()
    {
        return Arrays.concatenate(t, rho);
    }

    public byte[] getEncoded()
    {
        return getPublicKey();
    }

    public KyberPublicKeyParameters(KyberParameters params, byte[] t, byte[] rho)
    {
        super(false, params);
        this.t = Arrays.clone(t);
        this.rho = Arrays.clone(rho);
    }

    public KyberPublicKeyParameters(KyberParameters params, byte[] encoding)
    {
        super(false, params);
        this.t = Arrays.copyOfRange(encoding, 0, encoding.length - KyberEngine.KyberSymBytes);
        this.rho = Arrays.copyOfRange(encoding, encoding.length - KyberEngine.KyberSymBytes, encoding.length);
    }

    public byte[] getT()
    {
        return Arrays.clone(t);
    }

    public byte[] getRho()
    {
        return Arrays.clone(rho);
    }
}
