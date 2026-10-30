package org.bouncycastle.bcpg;

import java.io.IOException;

/**
 * Public key of the SLH-DSA signature algorithms {@link PublicKeyAlgorithmTags#SLHDSA_SHAKE_128s},
 * {@link PublicKeyAlgorithmTags#SLHDSA_SHAKE_128f} and {@link PublicKeyAlgorithmTags#SLHDSA_SHAKE_256s}
 * (RFC 9980 sec. 6.2.2.1): the fixed-length SLH-DSA public key in the FIPS 205 encoding (PK.seed || PK.root).
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-6.2.2.1">
 *     RFC 9980 - Public Key Packets (SLH-DSA)</a>
 */
public class SLHDSAPublicBCPGKey
    extends OctetArrayBCPGKey
{
    private final int algorithm;

    /**
     * Parse the public key of the given SLH-DSA algorithm from the packet stream.
     *
     * @param algorithm public key algorithm ID, one of the SLH-DSA code points
     * @param in packet input stream positioned at the algorithm-specific key material
     * @throws IOException if the key cannot be read
     */
    public SLHDSAPublicBCPGKey(int algorithm, BCPGInputStream in)
        throws IOException
    {
        super(getLength(algorithm), in);
        this.algorithm = algorithm;
    }

    /**
     * Construct the public key of the given SLH-DSA algorithm.
     *
     * @param algorithm public key algorithm ID, one of the SLH-DSA code points
     * @param key the SLH-DSA public key, 32 octets for the 128-bit parameter sets and 64 for SLH-DSA-SHAKE-256s
     */
    public SLHDSAPublicBCPGKey(int algorithm, byte[] key)
    {
        super(getLength(algorithm), key);
        this.algorithm = algorithm;
    }

    /**
     * Return the public key algorithm ID this key belongs to.
     *
     * @return one of the SLH-DSA code points
     */
    public int getAlgorithm()
    {
        return algorithm;
    }

    /**
     * Return the length of the SLH-DSA public key (RFC 9980 Table 8).
     *
     * @param algorithm public key algorithm ID
     * @return 32 for SLH-DSA-SHAKE-128s and -128f, 64 for SLH-DSA-SHAKE-256s
     */
    public static int getLength(int algorithm)
    {
        switch (algorithm)
        {
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s:
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f:
            return 32;
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s:
            return 64;
        default:
            throw new IllegalArgumentException("not an SLH-DSA algorithm: " + algorithm);
        }
    }

    /**
     * Return the length of an SLH-DSA signature (RFC 9980 Table 8).
     *
     * @param algorithm public key algorithm ID
     * @return 7856 for SLH-DSA-SHAKE-128s, 17088 for SLH-DSA-SHAKE-128f, 29792 for SLH-DSA-SHAKE-256s
     */
    public static int getSignatureLength(int algorithm)
    {
        switch (algorithm)
        {
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s:
            return 7856;
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f:
            return 17088;
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s:
            return 29792;
        default:
            throw new IllegalArgumentException("not an SLH-DSA algorithm: " + algorithm);
        }
    }
}
