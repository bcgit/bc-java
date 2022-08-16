package org.bouncycastle.pqc.crypto.ntruprime;

import org.bouncycastle.util.Arrays;

public class NTRULPRimePrivateKeyParameters
    extends NTRULPRimeKeyParameters
{
    private final byte[] enca;
    private final byte[] pk;
    private final byte[] rho;
    private final String hashAlgorithm;
    private final byte[] hash;

    public NTRULPRimePrivateKeyParameters(NTRULPRimeParameters params, byte[] enca, byte[] pk, byte[] rho, String hashAlgorithm, byte[] hash)
    {
        super(true, params);
        this.enca = Arrays.clone(enca);
        this.pk = Arrays.clone(pk);
        this.rho = Arrays.clone(rho);
        this.hashAlgorithm = hashAlgorithm;
        this.hash = Arrays.clone(hash);
    }

    byte[] getEnca()
    {
        return enca;
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
        return hash;
    }

    public byte[] getEncoded()
    {
        byte[] key = new byte[getParameters().getPrivateKeyBytes()];
        System.arraycopy(enca, 0, key, 0, enca.length);
        System.arraycopy(pk, 0, key, enca.length, pk.length);
        System.arraycopy(rho, 0, key, enca.length + pk.length, rho.length);
        System.arraycopy(hash, 0, key, enca.length + pk.length + rho.length, hash.length / 2);
        return key;
    }
}
