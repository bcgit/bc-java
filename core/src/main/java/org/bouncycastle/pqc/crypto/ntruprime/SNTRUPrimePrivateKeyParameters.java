package org.bouncycastle.pqc.crypto.ntruprime;

import org.bouncycastle.util.Arrays;

public class SNTRUPrimePrivateKeyParameters
    extends SNTRUPrimeKeyParameters
{
    private final byte[] f;
    private final byte[] ginv;
    private final byte[] pk;
    private final byte[] rho;
    private final String hashAlgorithm;
    private final byte[] hash;

    public SNTRUPrimePrivateKeyParameters(SNTRUPrimeParameters params, byte[] f, byte[] ginv,
                                          byte[] pk, byte[] rho, String hashAlgorithm, byte[] hash)
    {
        super(true, params);
        this.f = Arrays.clone(f);
        this.ginv = Arrays.clone(ginv);
        this.pk = Arrays.clone(pk);
        this.rho = Arrays.clone(rho);
        this.hashAlgorithm = hashAlgorithm;
        this.hash = Arrays.clone(hash);
    }

    byte[] getF()
    {
        return f;
    }

    byte[] getGinv()
    {
        return ginv;
    }

    byte[] getPk()
    {
        return pk;
    }

    byte[] getRho()
    {
        return rho;
    }

    String getHashAlgorithm()
    {
        return hashAlgorithm;
    }

    byte[] getHash()
    {
        return Arrays.clone(hash);
    }

    public byte[] getKey()
    {
        byte[] key = new byte[getParameters().getPrivateKeyBytes()];
        System.arraycopy(f, 0, key, 0, f.length);
        System.arraycopy(ginv, 0, key, f.length, ginv.length);
        System.arraycopy(pk, 0, key, f.length + ginv.length, pk.length);
        System.arraycopy(rho, 0, key, f.length + ginv.length + pk.length, rho.length);
        System.arraycopy(hash, 0, key, f.length + ginv.length + pk.length + rho.length, hash.length / 2);
        return key;
    }
}
