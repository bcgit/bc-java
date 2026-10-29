package org.bouncycastle.bcpg;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

/**
 * Public key of the ML-DSA + EdDSA composite signature algorithms {@link PublicKeyAlgorithmTags#MLDSA65_Ed25519}
 * and {@link PublicKeyAlgorithmTags#MLDSA87_Ed448} (RFC 9980 sec. 5.3.2.1): the fixed-length EdDSA public key
 * in the RFC 8032 encoding of its curve, followed by the fixed-length ML-DSA public key in the FIPS 204 encoding.
 * <p>
 * The component lengths are fixed by the algorithm ID (RFC 9980 Tables 6 and 7), so the key knows which
 * algorithm it belongs to and the two components can be read back with {@link #getEdDSAPublicKey()} and
 * {@link #getMLDSAPublicKey()}.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-5.3.2.1">
 *     RFC 9980 - Public Key Packets (ML-DSA + EdDSA)</a>
 */
public class MLDSACompositePublicBCPGKey
    extends OctetArrayBCPGKey
{
    private final int algorithm;

    /**
     * Parse the public key of the given composite algorithm from the packet stream.
     *
     * @param algorithm public key algorithm ID, {@link PublicKeyAlgorithmTags#MLDSA65_Ed25519} or
     *                  {@link PublicKeyAlgorithmTags#MLDSA87_Ed448}
     * @param in packet input stream positioned at the algorithm-specific key material
     * @throws IOException if the key cannot be read
     */
    public MLDSACompositePublicBCPGKey(int algorithm, BCPGInputStream in)
        throws IOException
    {
        super(getLength(algorithm), in);
        this.algorithm = algorithm;
    }

    /**
     * Construct the public key of the given composite algorithm from its two components.
     *
     * @param algorithm public key algorithm ID, {@link PublicKeyAlgorithmTags#MLDSA65_Ed25519} or
     *                  {@link PublicKeyAlgorithmTags#MLDSA87_Ed448}
     * @param eddsaPublicKey the Ed25519 (32 octets) or Ed448 (57 octets) public key
     * @param mldsaPublicKey the ML-DSA-65 (1952 octets) or ML-DSA-87 (2592 octets) public key
     */
    public MLDSACompositePublicBCPGKey(int algorithm, byte[] eddsaPublicKey, byte[] mldsaPublicKey)
    {
        super(getLength(algorithm), concatenate(algorithm, eddsaPublicKey, mldsaPublicKey));
        this.algorithm = algorithm;
    }

    private static byte[] concatenate(int algorithm, byte[] eddsaPublicKey, byte[] mldsaPublicKey)
    {
        MLKEMCompositePublicBCPGKey.checkLength("EdDSA public key", getEdDSAPublicKeyLength(algorithm), eddsaPublicKey);
        MLKEMCompositePublicBCPGKey.checkLength("ML-DSA public key", getMLDSAPublicKeyLength(algorithm), mldsaPublicKey);
        return Arrays.concatenate(eddsaPublicKey, mldsaPublicKey);
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
     * Return the EdDSA (Ed25519 or Ed448) public key component.
     *
     * @return EdDSA public key in RFC 8032 encoding
     */
    public byte[] getEdDSAPublicKey()
    {
        byte[] key = getKey();
        return Arrays.copyOf(key, getEdDSAPublicKeyLength(algorithm));
    }

    /**
     * Return the ML-DSA public key component.
     *
     * @return ML-DSA public key in FIPS 204 encoding
     */
    public byte[] getMLDSAPublicKey()
    {
        byte[] key = getKey();
        return Arrays.copyOfRange(key, getEdDSAPublicKeyLength(algorithm), key.length);
    }

    /**
     * Return the length of the algorithm-specific public key material for the given composite algorithm.
     *
     * @param algorithm public key algorithm ID
     * @return total octet length of the EdDSA and ML-DSA public keys
     */
    public static int getLength(int algorithm)
    {
        return getEdDSAPublicKeyLength(algorithm) + getMLDSAPublicKeyLength(algorithm);
    }

    /**
     * Return the length of the EdDSA public key component (RFC 9980 Table 6).
     *
     * @param algorithm public key algorithm ID
     * @return 32 for Ed25519, 57 for Ed448
     */
    public static int getEdDSAPublicKeyLength(int algorithm)
    {
        switch (algorithm)
        {
        case PublicKeyAlgorithmTags.MLDSA65_Ed25519:
            return Ed25519PublicBCPGKey.LENGTH;
        case PublicKeyAlgorithmTags.MLDSA87_Ed448:
            return Ed448PublicBCPGKey.LENGTH;
        default:
            throw new IllegalArgumentException("not an ML-DSA composite algorithm: " + algorithm);
        }
    }

    /**
     * Return the length of the ML-DSA public key component (RFC 9980 Table 7).
     *
     * @param algorithm public key algorithm ID
     * @return 1952 for ML-DSA-65, 2592 for ML-DSA-87
     */
    public static int getMLDSAPublicKeyLength(int algorithm)
    {
        switch (algorithm)
        {
        case PublicKeyAlgorithmTags.MLDSA65_Ed25519:
            return 1952;
        case PublicKeyAlgorithmTags.MLDSA87_Ed448:
            return 2592;
        default:
            throw new IllegalArgumentException("not an ML-DSA composite algorithm: " + algorithm);
        }
    }

    /**
     * Return the length of the EdDSA signature component of a composite signature (RFC 9980 Table 6).
     *
     * @param algorithm public key algorithm ID
     * @return 64 for Ed25519, 114 for Ed448
     */
    public static int getEdDSASignatureLength(int algorithm)
    {
        switch (algorithm)
        {
        case PublicKeyAlgorithmTags.MLDSA65_Ed25519:
            return 64;
        case PublicKeyAlgorithmTags.MLDSA87_Ed448:
            return 114;
        default:
            throw new IllegalArgumentException("not an ML-DSA composite algorithm: " + algorithm);
        }
    }

    /**
     * Return the length of the ML-DSA signature component of a composite signature (RFC 9980 Table 7).
     *
     * @param algorithm public key algorithm ID
     * @return 3309 for ML-DSA-65, 4627 for ML-DSA-87
     */
    public static int getMLDSASignatureLength(int algorithm)
    {
        switch (algorithm)
        {
        case PublicKeyAlgorithmTags.MLDSA65_Ed25519:
            return 3309;
        case PublicKeyAlgorithmTags.MLDSA87_Ed448:
            return 4627;
        default:
            throw new IllegalArgumentException("not an ML-DSA composite algorithm: " + algorithm);
        }
    }

    /**
     * Return the total length of a composite signature: the EdDSA signature followed by the ML-DSA signature
     * (RFC 9980 sec. 5.3.1).
     *
     * @param algorithm public key algorithm ID
     * @return 3373 for ML-DSA-65 + Ed25519, 4741 for ML-DSA-87 + Ed448
     */
    public static int getSignatureLength(int algorithm)
    {
        return getEdDSASignatureLength(algorithm) + getMLDSASignatureLength(algorithm);
    }
}
