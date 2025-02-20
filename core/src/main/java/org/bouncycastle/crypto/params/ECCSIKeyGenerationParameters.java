package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

public class ECCSIKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final BigInteger q;
    private final ECPoint G;
    private final Digest digest;
    private final byte[] id;
    private final BigInteger ksak;
    private final ECPoint kpak;
    private final int n;

    /**
     * initialise the generator with a source of randomness
     * and a strength (in bits).
     *
     * @param random the random byte source.
     */
    public ECCSIKeyGenerationParameters(SecureRandom random, X9ECParameters params, Digest digest, byte[] id)
    {
        super(random, params.getCurve().getA().bitLength());
        this.q = params.getCurve().getOrder();
        this.G = params.getG();
        this.digest = digest;
        this.id = Arrays.clone(id);
        this.n = params.getCurve().getA().bitLength();
        this.ksak = new BigInteger(n, random).mod(q);
        this.kpak = G.multiply(ksak).normalize();
    }

    public byte[] getId()
    {
        return id;
    }

    public ECPoint getKPAK()
    {
        return kpak;
    }

    public BigInteger computeSSK(BigInteger hs_v)
    {
        return ksak.add(hs_v).mod(q);
    }

    public BigInteger getQ()
    {
        return q;
    }

    public ECPoint getG()
    {
        return G;
    }

    public Digest getDigest()
    {
        return digest;
    }

    public int getN()
    {
        return n;
    }
}
