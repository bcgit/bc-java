package org.bouncycastle.bcpg;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

/**
 * Secret key of the ML-DSA + EdDSA composite signature algorithms {@link PublicKeyAlgorithmTags#MLDSA65_Ed25519}
 * and {@link PublicKeyAlgorithmTags#MLDSA87_Ed448} (RFC 9980 sec. 5.3.2.2): the fixed-length EdDSA secret key
 * in the RFC 8032 encoding of its curve, followed by the 32 octet ML-DSA secret key in seed format - the value
 * xi of FIPS 204 ML-DSA.KeyGen, from which the signing key is expanded with ML-DSA.KeyGen_internal before use.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-5.3.2.2">
 *     RFC 9980 - Secret Key Packets (ML-DSA + EdDSA)</a>
 */
public class MLDSACompositeSecretBCPGKey
    extends OctetArrayBCPGKey
{
    /**
     * Length of the ML-DSA secret key in seed format (xi).
     */
    public static final int MLDSA_SEED_LENGTH = 32;

    private final int algorithm;

    /**
     * Parse the secret key of the given composite algorithm from the (decrypted) secret key material.
     *
     * @param algorithm public key algorithm ID, {@link PublicKeyAlgorithmTags#MLDSA65_Ed25519} or
     *                  {@link PublicKeyAlgorithmTags#MLDSA87_Ed448}
     * @param in input stream positioned at the algorithm-specific secret key material
     * @throws IOException if the key cannot be read
     */
    public MLDSACompositeSecretBCPGKey(int algorithm, BCPGInputStream in)
        throws IOException
    {
        super(getLength(algorithm), in);
        this.algorithm = algorithm;
    }

    /**
     * Construct the secret key of the given composite algorithm from its two components.
     *
     * @param algorithm public key algorithm ID, {@link PublicKeyAlgorithmTags#MLDSA65_Ed25519} or
     *                  {@link PublicKeyAlgorithmTags#MLDSA87_Ed448}
     * @param eddsaSecretKey the Ed25519 (32 octets) or Ed448 (57 octets) secret key
     * @param mldsaSeed the 32 octet ML-DSA seed xi
     */
    public MLDSACompositeSecretBCPGKey(int algorithm, byte[] eddsaSecretKey, byte[] mldsaSeed)
    {
        super(getLength(algorithm), concatenate(algorithm, eddsaSecretKey, mldsaSeed));
        this.algorithm = algorithm;
    }

    private static byte[] concatenate(int algorithm, byte[] eddsaSecretKey, byte[] mldsaSeed)
    {
        MLKEMCompositePublicBCPGKey.checkLength("EdDSA secret key", getEdDSASecretKeyLength(algorithm), eddsaSecretKey);
        MLKEMCompositePublicBCPGKey.checkLength("ML-DSA seed", MLDSA_SEED_LENGTH, mldsaSeed);
        return Arrays.concatenate(eddsaSecretKey, mldsaSeed);
    }

    /**
     * Return the public key algorithm ID this key belongs to.
     *
     * @return {@link PublicKeyAlgorithmTags#MLDSA65_Ed25519} or {@link PublicKeyAlgorithmTags#MLDSA87_Ed448}
     */
    public int getAlgorithm()
    {
        return algorithm;
    }

    /**
     * Return the EdDSA (Ed25519 or Ed448) secret key component.
     *
     * @return EdDSA secret key in RFC 8032 encoding
     */
    public byte[] getEdDSASecretKey()
    {
        byte[] key = getKey();
        return Arrays.copyOf(key, getEdDSASecretKeyLength(algorithm));
    }

    /**
     * Return the ML-DSA seed xi.
     *
     * @return 32 octet ML-DSA seed
     */
    public byte[] getMLDSASeed()
    {
        byte[] key = getKey();
        return Arrays.copyOfRange(key, getEdDSASecretKeyLength(algorithm), key.length);
    }

    /**
     * Return the length of the algorithm-specific secret key material for the given composite algorithm.
     *
     * @param algorithm public key algorithm ID
     * @return total octet length of the EdDSA secret key and the ML-DSA seed
     */
    public static int getLength(int algorithm)
    {
        return getEdDSASecretKeyLength(algorithm) + MLDSA_SEED_LENGTH;
    }

    /**
     * Return the length of the EdDSA secret key component (RFC 9980 Table 6).
     *
     * @param algorithm public key algorithm ID
     * @return 32 for Ed25519, 57 for Ed448
     */
    public static int getEdDSASecretKeyLength(int algorithm)
    {
        switch (algorithm)
        {
        case PublicKeyAlgorithmTags.MLDSA65_Ed25519:
            return Ed25519SecretBCPGKey.LENGTH;
        case PublicKeyAlgorithmTags.MLDSA87_Ed448:
            return Ed448SecretBCPGKey.LENGTH;
        default:
            throw new IllegalArgumentException("not an ML-DSA composite algorithm: " + algorithm);
        }
    }
}
