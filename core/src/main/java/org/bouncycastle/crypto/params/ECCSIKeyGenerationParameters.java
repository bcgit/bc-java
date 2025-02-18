package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

public class ECCSIKeyGenerationParameters
    extends KeyGenerationParameters
{
    private static final X9ECParameters params = CustomNamedCurves.getByName("secP256r1");
    private static final ECCurve curve = params.getCurve();

    private static final BigInteger q = ((ECCurve.Fp)curve).getQ();

    //BigInteger p = ((ECCurve.Fp)curve).getOrder();

    // The subgroup order is available as:
    //BigInteger n = params.getN();

    // And the base point (generator) is:
    private static final ECPoint G = params.getG();
    private final byte[] id;
    private final BigInteger ksak;
    private final ECPoint kpak;

    /**
     * initialise the generator with a source of randomness
     * and a strength (in bits).
     *
     * @param random the random byte source.
     */
    public ECCSIKeyGenerationParameters(SecureRandom random, byte[] id)
    {
        super(random, 256);
        this.id = Arrays.clone(id);
        this.ksak = new BigInteger(256, random).mod(q);
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
}
