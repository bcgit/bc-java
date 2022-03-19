package org.bouncycastle.pqc.crypto.sphincsplus;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class SPHINCSPlusPublicKeyParameters
    extends SPHINCSPlusKeyParameters
{
    private final PK pk;

    public SPHINCSPlusPublicKeyParameters(SPHINCSPlusParameters parameters, byte[] pkEncoded)
    {
        super(false, parameters);
        int n = parameters.getEngine().N;
        if (pkEncoded.length != 2 * n)
        {
            throw new IllegalArgumentException("public key encoding does not match parameters");
        }
        this.pk = new PK(Arrays.copyOfRange(pkEncoded, 0, n), Arrays.copyOfRange(pkEncoded, n, 2 * n));
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
        return Arrays.concatenate(Pack.intToBigEndian(SPHINCSPlusParameters.getID(getParameters()).intValue()), pk.seed, pk.root);
    }
}
