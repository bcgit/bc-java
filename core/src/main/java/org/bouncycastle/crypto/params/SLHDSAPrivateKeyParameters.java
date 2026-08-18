package org.bouncycastle.crypto.params;

import javax.security.auth.Destroyable;

import org.bouncycastle.util.Arrays;

public class SLHDSAPrivateKeyParameters
    extends SLHDSAKeyParameters
    implements Destroyable
{
    final SK sk;
    final PK pk;

    private volatile boolean destroyed;

    public SLHDSAPrivateKeyParameters(SLHDSAParameters parameters, byte[] skpkEncoded)
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

    public SLHDSAPrivateKeyParameters(SLHDSAParameters parameters, byte[] skSeed, byte[] prf, byte[] pkSeed, byte[] pkRoot)
    {
        super(true, parameters);
        this.sk = new SK(skSeed, prf);
        this.pk = new PK(pkSeed, pkRoot);
    }

    SLHDSAPrivateKeyParameters(SLHDSAParameters parameters, SK sk, PK pk)
    {
        super(true, parameters);
        this.sk = sk;
        this.pk = pk;
    }

    public byte[] getSeed()
    {
        return cloneWithCheck(sk.seed);
    }

    public byte[] getPrf()
    {
        return cloneWithCheck(sk.prf);
    }

    public byte[] getPublicSeed()
    {
        return cloneWithCheck(pk.seed);
    }

    public byte[] getRoot()
    {
        return cloneWithCheck(pk.root);
    }

    public byte[] getPublicKey()
    {
        return cloneWithCheck(Arrays.concatenate(pk.seed, pk.root));
    }

    public byte[] getEncoded()
    {
        return cloneWithCheck(Arrays.concatenate(new byte[][]{sk.seed, sk.prf, pk.seed, pk.root}));
    }

    public byte[] getEncodedPublicKey()
    {
        return cloneWithCheck(Arrays.concatenate(pk.seed, pk.root));
    }

    /**
     * Zeroize the secret key material held by this object.
     */
    public synchronized void destroy()
    {
        if (!destroyed)
        {
            destroyed = true;
            Arrays.clear(sk.seed);
            Arrays.clear(sk.prf);
            Arrays.clear(pk.seed);
            Arrays.clear(pk.root);
        }
    }

    public boolean isDestroyed()
    {
        return destroyed;
    }

    private byte[] cloneWithCheck(byte[] fieldValue)
    {
        byte[] rv = Arrays.clone(fieldValue);
        if (destroyed)
        {
            throw new IllegalStateException("key destroyed");
        }

        return rv;
    }

    private static class PK
    {
        final byte[] seed;
        final byte[] root;

        PK(byte[] seed, byte[] root)
        {
            this.seed = seed;
            this.root = root;
        }
    }

    private static class SK
    {
        final byte[] seed;
        final byte[] prf;

        SK(byte[] seed, byte[] prf)
        {
            this.seed = seed;
            this.prf = prf;
        }
    }
}
