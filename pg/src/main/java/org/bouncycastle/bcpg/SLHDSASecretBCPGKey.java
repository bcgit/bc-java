package org.bouncycastle.bcpg;

import java.io.IOException;

/**
 * Secret key of the SLH-DSA signature algorithms {@link PublicKeyAlgorithmTags#SLHDSA_SHAKE_128s},
 * {@link PublicKeyAlgorithmTags#SLHDSA_SHAKE_128f} and {@link PublicKeyAlgorithmTags#SLHDSA_SHAKE_256s}
 * (RFC 9980 sec. 6.2.2.2): the fixed-length SLH-DSA secret key in the FIPS 205 encoding
 * (SK.seed || SK.prf || PK.seed || PK.root).
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-6.2.2.2">
 *     RFC 9980 - Secret Key Packets (SLH-DSA)</a>
 */
public class SLHDSASecretBCPGKey
    extends OctetArrayBCPGKey
{
    private final int algorithm;

    /**
     * Parse the secret key of the given SLH-DSA algorithm from the (decrypted) secret key material.
     *
     * @param algorithm public key algorithm ID, one of the SLH-DSA code points
     * @param in input stream positioned at the algorithm-specific secret key material
     * @throws IOException if the key cannot be read
     */
    public SLHDSASecretBCPGKey(int algorithm, BCPGInputStream in)
        throws IOException
    {
        super(getLength(algorithm), in);
        this.algorithm = algorithm;
    }

    /**
     * Construct the secret key of the given SLH-DSA algorithm.
     *
     * @param algorithm public key algorithm ID, one of the SLH-DSA code points
     * @param key the SLH-DSA secret key, 64 octets for the 128-bit parameter sets and 128 for SLH-DSA-SHAKE-256s
     */
    public SLHDSASecretBCPGKey(int algorithm, byte[] key)
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
     * Return the length of the SLH-DSA secret key (RFC 9980 Table 8).
     *
     * @param algorithm public key algorithm ID
     * @return 64 for SLH-DSA-SHAKE-128s and -128f, 128 for SLH-DSA-SHAKE-256s
     */
    public static int getLength(int algorithm)
    {
        return 2 * SLHDSAPublicBCPGKey.getLength(algorithm);
    }
}
