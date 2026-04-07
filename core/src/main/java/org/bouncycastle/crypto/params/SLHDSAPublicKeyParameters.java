package org.bouncycastle.crypto.params;

import org.bouncycastle.util.Arrays;

public class SLHDSAPublicKeyParameters
    extends SLHDSAKeyParameters
{
    private final byte[] pkSeed;
    private final byte[] pkRoot;

    public SLHDSAPublicKeyParameters(SLHDSAParameters parameters, byte[] pkValues)
    {
        super(false, parameters);
        int n = parameters.getN();
        if (pkValues.length != 2 * n)
        {
            throw new IllegalArgumentException("public key encoding does not match parameters");
        }
        this.pkSeed = Arrays.copyOfRange(pkValues, 0, n);
        this.pkRoot = Arrays.copyOfRange(pkValues, n, 2 * n);
    }

    public byte[] getSeed()
    {
        return Arrays.clone(pkSeed);
    }

    public byte[] getRoot()
    {
        return Arrays.clone(pkRoot);
    }

    public byte[] getEncoded()
    {
        return Arrays.concatenate(pkSeed, pkRoot);
    }
}
