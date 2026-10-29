package org.bouncycastle.bcpg;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

/**
 * Public key of the ML-KEM + ECDH composite encryption algorithms {@link PublicKeyAlgorithmTags#MLKEM768_X25519}
 * and {@link PublicKeyAlgorithmTags#MLKEM1024_X448} (RFC 9980 sec. 4.3.2.1): the fixed-length ECDH public key
 * in the RFC 7748 encoding of its curve, followed by the fixed-length ML-KEM encapsulation key in the FIPS 203
 * encoding.
 * <p>
 * The component lengths are fixed by the algorithm ID (RFC 9980 Tables 3 and 4), so the key knows which
 * algorithm it belongs to and the two components can be read back with {@link #getECDHPublicKey()} and
 * {@link #getMLKEMPublicKey()}.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-4.3.2.1">
 *     RFC 9980 - Public Key Packets (ML-KEM + ECDH)</a>
 */
public class MLKEMCompositePublicBCPGKey
    extends OctetArrayBCPGKey
{
    private final int algorithm;

    /**
     * Parse the public key of the given composite algorithm from the packet stream.
     *
     * @param algorithm public key algorithm ID, {@link PublicKeyAlgorithmTags#MLKEM768_X25519} or
     *                  {@link PublicKeyAlgorithmTags#MLKEM1024_X448}
     * @param in packet input stream positioned at the algorithm-specific key material
     * @throws IOException if the key cannot be read
     */
    public MLKEMCompositePublicBCPGKey(int algorithm, BCPGInputStream in)
        throws IOException
    {
        super(getLength(algorithm), in);
        this.algorithm = algorithm;
    }

    /**
     * Construct the public key of the given composite algorithm from its two components.
     *
     * @param algorithm public key algorithm ID, {@link PublicKeyAlgorithmTags#MLKEM768_X25519} or
     *                  {@link PublicKeyAlgorithmTags#MLKEM1024_X448}
     * @param ecdhPublicKey the X25519 (32 octets) or X448 (56 octets) public key
     * @param mlkemPublicKey the ML-KEM-768 (1184 octets) or ML-KEM-1024 (1568 octets) encapsulation key
     */
    public MLKEMCompositePublicBCPGKey(int algorithm, byte[] ecdhPublicKey, byte[] mlkemPublicKey)
    {
        super(getLength(algorithm), concatenate(algorithm, ecdhPublicKey, mlkemPublicKey));
        this.algorithm = algorithm;
    }

    private static byte[] concatenate(int algorithm, byte[] ecdhPublicKey, byte[] mlkemPublicKey)
    {
        checkLength("ECDH public key", getECDHPublicKeyLength(algorithm), ecdhPublicKey);
        checkLength("ML-KEM public key", getMLKEMPublicKeyLength(algorithm), mlkemPublicKey);
        return Arrays.concatenate(ecdhPublicKey, mlkemPublicKey);
    }

    static void checkLength(String name, int expected, byte[] value)
    {
        if (value == null || value.length != expected)
        {
            throw new IllegalArgumentException("unexpected " + name + " length: expected " + expected
                + " bytes, got " + (value == null ? "null" : String.valueOf(value.length)));
        }
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
     * Return the ECDH (X25519 or X448) public key component.
     *
     * @return ECDH public key in RFC 7748 encoding
     */
    public byte[] getECDHPublicKey()
    {
        byte[] key = getKey();
        return Arrays.copyOf(key, getECDHPublicKeyLength(algorithm));
    }

    /**
     * Return the ML-KEM encapsulation key component.
     *
     * @return ML-KEM public key in FIPS 203 encoding
     */
    public byte[] getMLKEMPublicKey()
    {
        byte[] key = getKey();
        return Arrays.copyOfRange(key, getECDHPublicKeyLength(algorithm), key.length);
    }

    /**
     * Return the length of the algorithm-specific public key material for the given composite algorithm.
     *
     * @param algorithm public key algorithm ID
     * @return total octet length of the ECDH and ML-KEM public keys
     */
    public static int getLength(int algorithm)
    {
        return getECDHPublicKeyLength(algorithm) + getMLKEMPublicKeyLength(algorithm);
    }

    /**
     * Return the length of the ECDH public key component (RFC 9980 Table 3).
     *
     * @param algorithm public key algorithm ID
     * @return 32 for X25519, 56 for X448
     */
    public static int getECDHPublicKeyLength(int algorithm)
    {
        switch (algorithm)
        {
        case PublicKeyAlgorithmTags.MLKEM768_X25519:
            return X25519PublicBCPGKey.LENGTH;
        case PublicKeyAlgorithmTags.MLKEM1024_X448:
            return X448PublicBCPGKey.LENGTH;
        default:
            throw new IllegalArgumentException("not an ML-KEM composite algorithm: " + algorithm);
        }
    }

    /**
     * Return the length of the ML-KEM encapsulation key component (RFC 9980 Table 4).
     *
     * @param algorithm public key algorithm ID
     * @return 1184 for ML-KEM-768, 1568 for ML-KEM-1024
     */
    public static int getMLKEMPublicKeyLength(int algorithm)
    {
        switch (algorithm)
        {
        case PublicKeyAlgorithmTags.MLKEM768_X25519:
            return 1184;
        case PublicKeyAlgorithmTags.MLKEM1024_X448:
            return 1568;
        default:
            throw new IllegalArgumentException("not an ML-KEM composite algorithm: " + algorithm);
        }
    }

    /**
     * Return the length of the ML-KEM ciphertext carried in a PKESK packet (RFC 9980 Table 4).
     *
     * @param algorithm public key algorithm ID
     * @return 1088 for ML-KEM-768, 1568 for ML-KEM-1024
     */
    public static int getMLKEMCiphertextLength(int algorithm)
    {
        switch (algorithm)
        {
        case PublicKeyAlgorithmTags.MLKEM768_X25519:
            return 1088;
        case PublicKeyAlgorithmTags.MLKEM1024_X448:
            return 1568;
        default:
            throw new IllegalArgumentException("not an ML-KEM composite algorithm: " + algorithm);
        }
    }
}
