package org.bouncycastle.pqc.crypto.crystals.kyber;

import org.bouncycastle.util.Arrays;

public class KyberPrivateKeyParameters
    extends KyberKeyParameters
{
    final byte[] s;
    final byte[] hpk;
    final byte[] nonce;
    final byte[] t;
    final byte[] rho;

    public KyberPrivateKeyParameters(KyberParameters params, byte[] s, byte[] hpk, byte[] nonce, byte[] t, byte[] rho)
    {
        super(true, params);
        this.s = Arrays.clone(s);
        this.hpk = Arrays.clone(hpk);
        this.nonce = Arrays.clone(nonce);
        this.t = Arrays.clone(t);
        this.rho = Arrays.clone(rho);
    }

    public byte[] getEncoded()
    {
        return Arrays.concatenate(new byte[][]{ s, t, rho, hpk, nonce });
    }

    public byte[] getHPK()
    {
        return Arrays.clone(hpk);
    }

    public byte[] getNonce()
    {
        return Arrays.clone(nonce);
    }

    /** @deprecated Use {@link #getEncoded()} instead. */
    public byte[] getPrivateKey()
    {
        return getEncoded();
    }

    public byte[] getPublicKey()
    {
        return KyberPublicKeyParameters.getEncoded(t, rho);
    }

    public KyberPublicKeyParameters getPublicKeyParameters()
    {
        return new KyberPublicKeyParameters(getParameters(), t, rho);
    }

    public byte[] getRho()
    {
        return Arrays.clone(rho);
    }

    public byte[] getS()
    {
        return Arrays.clone(s);
    }

    public byte[] getT()
    {
        return Arrays.clone(t);
    }
}
