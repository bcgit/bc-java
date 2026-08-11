package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECAlgorithms;
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
        if (z.signum() <= 0 || z.compareTo(SAKKEPublicKeyParameters.q) >= 0)
        {
            // RFC 6508 sec. 6.1 draws the master secret in [2, q-1], so a value outside [1, q-1]
            // is a malformed key. Checked here because SAKKEKEMExtractor adds it modulo q in a
            // form that requires it reduced, and unlike the public identifier it cannot simply be
            // reduced on the way in - that reduction is the variable-time step being avoided.
            // Note the [z]P == Z check below already rejects most out-of-range values; what this
            // adds is the one congruent to a valid z modulo q, which that check accepts.
            throw new IllegalArgumentException("master secret must be in [1, q-1]");
        }
        this.z = z;
        this.publicParams = publicParams;
        // z is the master secret: constant-time, not the curve's default wNAF multiplier
        ECPoint computed_Z = ECAlgorithms.multiplySecret(publicParams.getPoint(), z,
            SAKKEPublicKeyParameters.q).normalize();
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
        // z is the master secret: constant-time, not the curve's default wNAF multiplier
        this.publicParams = new SAKKEPublicKeyParameters(identifier,
            ECAlgorithms.multiplySecret(SAKKEPublicKeyParameters.P, z,
                SAKKEPublicKeyParameters.q).normalize());
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
