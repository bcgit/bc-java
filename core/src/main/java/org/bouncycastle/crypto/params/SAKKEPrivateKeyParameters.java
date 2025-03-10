package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

/**
 * Represents a private key for the Sakai-Kasahara Key Encryption (SAKKE) scheme, as defined in RFC 6508.
 *
 * <p>SAKKE is an identity-based public key encryption scheme designed for one-pass key establishment.
 * It is used in MIKEY-SAKKE for secure communication key distribution.</p>
 *
 * <p>This class generates and manages a SAKKE private key, which consists of a randomly generated
 * scalar {@code z}. The corresponding public key is computed as {@code Z = [z]P}, where {@code P}
 * is a publicly known generator point on the elliptic curve.</p>
 *
 * <p>The private key is used to derive the master secret in the key exchange process.</p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6508">RFC 6508: Sakai-Kasahara Key Encryption (SAKKE)</a>
 */
public class SAKKEPrivateKeyParameters
    extends AsymmetricKeyParameter
{
    private static final BigInteger qMinOne = SAKKEPublicKeyParameters.q.subtract(BigInteger.ONE);
    /**
     * The associated public key parameters.
     */
    private final SAKKEPublicKeyParameters publicParams;
    /**
     * The private key scalar (master secret).
     */
    private final BigInteger z;  // KMS Public Key: Z = [z]P

    /**
     * Constructs a SAKKE private key with a given private value and associated public parameters.
     *
     * @param z            The private key scalar.
     * @param publicParams The associated public key parameters.
     */
    public SAKKEPrivateKeyParameters(BigInteger z, SAKKEPublicKeyParameters publicParams)
    {
        super(true);
        this.z = z;
        this.publicParams = publicParams;
        ECPoint computed_Z = publicParams.getPoint().multiply(z).normalize();
        if (!computed_Z.equals(publicParams.getZ()))
        {
            throw new IllegalStateException("public key and private key of SAKKE do not match");
        }
    }

    /**
     * Generates a random SAKKE private key and its corresponding public key.
     *
     * <p>The private key scalar {@code z} is chosen randomly in the range [2, q-1],
     * where {@code q} is the order of the subgroup. The public key is computed as
     * {@code Z = [z]P}, where {@code P} is the public generator.</p>
     *
     * @param random A cryptographic random number generator.
     */
    public SAKKEPrivateKeyParameters(SecureRandom random)
    {
        super(true);
        this.z = BigIntegers.createRandomInRange(BigIntegers.TWO, qMinOne, random);
        BigInteger identifier = BigIntegers.createRandomInRange(BigIntegers.TWO, qMinOne, random);
        this.publicParams = new SAKKEPublicKeyParameters(identifier,
            SAKKEPublicKeyParameters.P.multiply(z).normalize());
    }

    /**
     * Retrieves the public key parameters associated with this private key.
     *
     * @return The corresponding SAKKE public key parameters.
     */
    public SAKKEPublicKeyParameters getPublicParams()
    {
        return publicParams;
    }

    /**
     * Retrieves the private key scalar (master secret).
     *
     * @return The private key scalar {@code z}.
     */
    public BigInteger getMasterSecret()
    {
        return z;
    }
}
