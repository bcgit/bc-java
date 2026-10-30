package org.bouncycastle.bcpg;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

/**
 * Secret key of the ML-KEM + ECDH composite encryption algorithms {@link PublicKeyAlgorithmTags#MLKEM768_X25519}
 * and {@link PublicKeyAlgorithmTags#MLKEM1024_X448} (RFC 9980 sec. 4.3.2.2): the fixed-length ECDH secret key
 * in the RFC 7748 encoding of its curve, followed by the 64 octet ML-KEM secret key in seed format - the
 * concatenation of the values d and z of FIPS 203 ML-KEM.KeyGen, from which the decapsulation key is expanded
 * with ML-KEM.KeyGen_internal before use.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-4.3.2.2">
 *     RFC 9980 - Secret Key Packets (ML-KEM + ECDH)</a>
 */
public class MLKEMCompositeSecretBCPGKey
    extends OctetArrayBCPGKey
{
    /**
     * Length of the ML-KEM secret key in seed format: d || z, 32 octets each.
     */
    public static final int MLKEM_SEED_LENGTH = 64;

    private final int algorithm;

    /**
     * Parse the secret key of the given composite algorithm from the (decrypted) secret key material.
     *
     * @param algorithm public key algorithm ID, {@link PublicKeyAlgorithmTags#MLKEM768_X25519} or
     *                  {@link PublicKeyAlgorithmTags#MLKEM1024_X448}
     * @param in input stream positioned at the algorithm-specific secret key material
     * @throws IOException if the key cannot be read
     */
    public MLKEMCompositeSecretBCPGKey(int algorithm, BCPGInputStream in)
        throws IOException
    {
        super(getLength(algorithm), in);
        this.algorithm = algorithm;
    }

    /**
     * Construct the secret key of the given composite algorithm from its two components.
     *
     * @param algorithm public key algorithm ID, {@link PublicKeyAlgorithmTags#MLKEM768_X25519} or
     *                  {@link PublicKeyAlgorithmTags#MLKEM1024_X448}
     * @param ecdhSecretKey the X25519 (32 octets) or X448 (56 octets) secret key
     * @param mlkemSeed the 64 octet ML-KEM seed d || z
     */
    public MLKEMCompositeSecretBCPGKey(int algorithm, byte[] ecdhSecretKey, byte[] mlkemSeed)
    {
        super(getLength(algorithm), concatenate(algorithm, ecdhSecretKey, mlkemSeed));
        this.algorithm = algorithm;
    }

    private static byte[] concatenate(int algorithm, byte[] ecdhSecretKey, byte[] mlkemSeed)
    {
        MLKEMCompositePublicBCPGKey.checkLength("ECDH secret key", getECDHSecretKeyLength(algorithm), ecdhSecretKey);
        MLKEMCompositePublicBCPGKey.checkLength("ML-KEM seed", MLKEM_SEED_LENGTH, mlkemSeed);
        return Arrays.concatenate(ecdhSecretKey, mlkemSeed);
    }

    /**
     * Return the public key algorithm ID this key belongs to.
     *
     * @return {@link PublicKeyAlgorithmTags#MLKEM768_X25519} or {@link PublicKeyAlgorithmTags#MLKEM1024_X448}
     */
    public int getAlgorithm()
    {
        return algorithm;
    }

    /**
     * Return the ECDH (X25519 or X448) secret key component.
     *
     * @return ECDH secret key in RFC 7748 encoding
     */
    public byte[] getECDHSecretKey()
    {
        byte[] key = getKey();
        return Arrays.copyOf(key, getECDHSecretKeyLength(algorithm));
    }

    /**
     * Return the ML-KEM seed d || z.
     *
     * @return 64 octet ML-KEM seed
     */
    public byte[] getMLKEMSeed()
    {
        byte[] key = getKey();
        return Arrays.copyOfRange(key, getECDHSecretKeyLength(algorithm), key.length);
    }

    /**
     * Return the length of the algorithm-specific secret key material for the given composite algorithm.
     *
     * @param algorithm public key algorithm ID
     * @return total octet length of the ECDH secret key and the ML-KEM seed
     */
    public static int getLength(int algorithm)
    {
        return getECDHSecretKeyLength(algorithm) + MLKEM_SEED_LENGTH;
    }

    /**
     * Return the length of the ECDH secret key component (RFC 9980 Table 3).
     *
     * @param algorithm public key algorithm ID
     * @return 32 for X25519, 56 for X448
     */
    public static int getECDHSecretKeyLength(int algorithm)
    {
        switch (algorithm)
        {
        case PublicKeyAlgorithmTags.MLKEM768_X25519:
            return X25519SecretBCPGKey.LENGTH;
        case PublicKeyAlgorithmTags.MLKEM1024_X448:
            return X448SecretBCPGKey.LENGTH;
        default:
            throw new IllegalArgumentException("not an ML-KEM composite algorithm: " + algorithm);
        }
    }
}
