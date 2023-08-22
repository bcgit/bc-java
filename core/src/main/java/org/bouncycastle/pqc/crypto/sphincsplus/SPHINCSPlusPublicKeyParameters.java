package org.bouncycastle.pqc.crypto.sphincsplus;

import org.bouncycastle.util.Arrays;

public class SPHINCSPlusPublicKeyParameters
    extends SPHINCSPlusKeyParameters
{
    private final PK pk;

    public SPHINCSPlusPublicKeyParameters(SPHINCSPlusParameters parameters, byte[] pkValues)
    {
        super(false, parameters);
        int n = parameters.getN();
        if (pkValues.length != 2 * n)
        {
            throw new IllegalArgumentException("public key encoding does not match parameters");
        }
        this.pk = new PK(Arrays.copyOfRange(pkValues, 0, n), Arrays.copyOfRange(pkValues, n, 2 * n));
    }
    
    SPHINCSPlusPublicKeyParameters(SPHINCSPlusParameters parameters, PK pk)
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
