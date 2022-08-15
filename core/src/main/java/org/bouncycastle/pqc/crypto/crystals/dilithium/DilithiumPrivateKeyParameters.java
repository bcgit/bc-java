package org.bouncycastle.pqc.crypto.crystals.dilithium;

import org.bouncycastle.util.Arrays;

public class DilithiumPrivateKeyParameters
    extends DilithiumKeyParameters
{
    protected final byte[] rho;
    protected final byte[] k;
    protected final byte[] tr;
    private final byte[] s1;
    private final byte[] s2;
    private final byte[] t0;

    public byte[] getPrivateKey()
    {
        return getEncoded();
    }

    public DilithiumPrivateKeyParameters(DilithiumParameters params, byte[] rho, byte[] K, byte[] tr, byte[] s1, byte[] s2, byte[] t0)
    {
        super(true, params);
        this.rho = Arrays.clone(rho);
        this.k = Arrays.clone(K);
        this.tr = Arrays.clone(tr);
        this.s1 = Arrays.clone(s1);
        this.s2 = Arrays.clone(s2);
        this.t0 = Arrays.clone(t0);
    }

    public byte[] getRho()
    {
        return Arrays.clone(rho);
    }

    public byte[] getK()
    {
        return Arrays.clone(k);
    }

    public byte[] getTr()
    {
        return Arrays.clone(tr);
    }

    public byte[] getS1()
    {
        return Arrays.clone(s1);
    }

    public byte[] getS2()
    {
        return Arrays.clone(s2);
    }

    public byte[] getT0()
    {
        return Arrays.clone(t0);
    }

    public byte[] getEncoded()
    {
        return Arrays.concatenate(new byte[][] { rho, k, tr, s1, s2, t0 });
    }
}
