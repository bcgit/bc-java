package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * Parameters for ECCSI key generation.
 *
 * <p>
 * This class encapsulates the parameters required for ECCSI (Elliptic Curve
 * Certificateless Signatures for Identity-based encryption) key generation.
 * It holds the elliptic curve domain parameters and computes the key pair
 * components used in ECCSI.
 * </p>
 *
 * <p>
 * The secret component {@code ksak} is generated randomly and reduced modulo
 * {@code q}, while {@code kpak} is derived from {@code ksak} by multiplying the
 * generator point.
 * </p>
 */
public class ECCSIKeyGenerationParameters
    extends KeyGenerationParameters
{
    /**
     * The order of the elliptic curve.
     */
    private final BigInteger q;

    /**
     * The generator (base point) of the elliptic curve.
     */
    private final ECPoint G;

    /**
     * The digest algorithm used in key generation.
     */
    private final Digest digest;

    /**
     * The identifier (e.g. user identity) used in key generation.
     */
    private final byte[] id;

    /**
     * The secret key component (ksak) used in ECCSI, generated randomly.
     */
    private final BigInteger ksak;

    /**
     * The public key component (kpak), computed as G * ksak.
     */
    private final ECPoint kpak;

    /**
     * The bit length used for key generation (typically the bit length of the curve's parameter A).
     */
    private final int n;

    /**
     * Constructs an instance of {@code ECCSIKeyGenerationParameters} with the specified
     * source of randomness, elliptic curve parameters, digest algorithm, and identifier.
     *
     * @param random the source of randomness.
     * @param params the elliptic curve parameters (in X9.62 format) providing the curve, order, and generator.
     * @param digest the digest algorithm to be used.
     * @param id     the identifier associated with the key generation (e.g. a user or device ID).
     */
    public ECCSIKeyGenerationParameters(SecureRandom random, X9ECParameters params, Digest digest, byte[] id)
    {
        super(random, params.getCurve().getA().bitLength());
        this.q = params.getCurve().getOrder();
        this.G = params.getG();
        this.digest = digest;
        this.id = Arrays.clone(id);
        this.n = params.getCurve().getA().bitLength();
        this.ksak = BigIntegers.createRandomBigInteger(n, random).mod(q);
        this.kpak = G.multiply(ksak).normalize();
    }

    /**
     * Returns a copy of the identifier used in these parameters.
     *
     * @return a byte array containing the identifier.
     */
    public byte[] getId()
    {
        return Arrays.clone(id);
    }

    /**
     * Returns the public key component (kpak) corresponding to the secret key.
     *
     * @return the public key point.
     */
    public ECPoint getKPAK()
    {
        return kpak;
    }

    /**
     * Computes the session secret key (SSK) by adding the provided value to the secret key component
     * and reducing modulo the curve order.
     *
     * @param hs_v a BigInteger value (typically derived from a hash) to be added to the secret.
     * @return the computed session secret key.
     */
    public BigInteger computeSSK(BigInteger hs_v)
    {
        return ksak.add(hs_v).mod(q);
    }

    /**
     * Returns the order of the elliptic curve.
     *
     * @return the curve order.
     */
    public BigInteger getQ()
    {
        return q;
    }

    /**
     * Returns the generator (base point) of the elliptic curve.
     *
     * @return the generator point.
     */
    public ECPoint getG()
    {
        return G;
    }

    /**
     * Returns the digest algorithm used for key generation.
     *
     * @return the digest.
     */
    public Digest getDigest()
    {
        return digest;
    }

    /**
     * Returns the bit length used in key generation.
     *
     * @return the bit length.
     */
    public int getN()
    {
        return n;
    }
}
