package org.bouncycastle.pqc.crypto.sphincsplus;

import org.bouncycastle.util.Arrays;

public class SPHINCSPlusPrivateKeyParameters
    extends SPHINCSPlusKeyParameters
{
    final SK sk;
    final PK pk;

    public SPHINCSPlusPrivateKeyParameters(SPHINCSPlusParameters parameters, byte[] skpkEncoded)
    {
        super(true, parameters);
        int n = parameters.getN();
        if (skpkEncoded.length != 4 * n)
        {
            throw new IllegalArgumentException("private key encoding does not match parameters");
        }
        this.sk = new SK(Arrays.copyOfRange(skpkEncoded, 0, n), Arrays.copyOfRange(skpkEncoded, n, 2 * n));
        this.pk = new PK(Arrays.copyOfRange(skpkEncoded, 2 * n, 3 * n), Arrays.copyOfRange(skpkEncoded, 3 * n, 4 * n));
    }

    public SPHINCSPlusPrivateKeyParameters(SPHINCSPlusParameters parameters, byte[] skSeed, byte[] prf, byte[] pkSeed, byte[] pkRoot)
    {
        super(true, parameters);
        this.sk = new SK(skSeed, prf);
        this.pk = new PK(pkSeed, pkRoot);
    }
    SPHINCSPlusPrivateKeyParameters(SPHINCSPlusParameters parameters, SK sk, PK pk)
    {
        super(true, parameters);
        this.sk = sk;
        this.pk = pk;
    }

    public byte[] getSeed()
    {
        return Arrays.clone(sk.seed);
    }

    public byte[] getPrf()
    {
        return Arrays.clone(sk.prf);
    }

    public byte[] getPublicSeed()
    {
        return Arrays.clone(pk.seed);
    }
    public byte[] getRoot()
    {
        return Arrays.clone(pk.root);
    }

    public byte[] getPublicKey()
    {
        return Arrays.concatenate(pk.seed, pk.root);
    }

    public byte[] getEncoded()
    {
        return Arrays.concatenate(new byte[][]{ sk.seed, sk.prf, pk.seed, pk.root });
    }

    public byte[] getEncodedPublicKey()
    {
        return Arrays.concatenate(pk.seed, pk.root);
    }
}
