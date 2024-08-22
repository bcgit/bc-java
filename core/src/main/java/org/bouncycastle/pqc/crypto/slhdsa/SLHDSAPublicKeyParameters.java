package org.bouncycastle.pqc.crypto.slhdsa;

import org.bouncycastle.util.Arrays;

public class SLHDSAPublicKeyParameters
    extends SLHDSAKeyParameters
{
    private final PK pk;

    public SLHDSAPublicKeyParameters(SLHDSAParameters parameters, byte[] pkValues)
    {
        super(false, parameters);
        int n = parameters.getN();
        if (pkValues.length != 2 * n)
        {
            throw new IllegalArgumentException("public key encoding does not match parameters");
        }
        this.pk = new PK(Arrays.copyOfRange(pkValues, 0, n), Arrays.copyOfRange(pkValues, n, 2 * n));
    }
    
    SLHDSAPublicKeyParameters(SLHDSAParameters parameters, PK pk)
    {
        super(false, parameters);
        this.pk = pk;
    }

    public byte[] getSeed()
    {
        return Arrays.clone(pk.seed);
    }

    public byte[] getRoot()
    {
        return Arrays.clone(pk.root);
    }

    public byte[] getEncoded()
    {
        return Arrays.concatenate(pk.seed, pk.root);
    }
}
