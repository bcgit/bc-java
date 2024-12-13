package org.bouncycastle.kmip.wire.enumeration;

/**
 * The DigitalSignatureAlgorithm enum represents various algorithms used for digital signatures.
 */
public enum KMIPDigitalSignatureAlgorithm
{
    MD2_WITH_RSA_ENCRYPTION(0x01),             // MD2 with RSA Encryption
    MD5_WITH_RSA_ENCRYPTION(0x02),             // MD5 with RSA Encryption
    SHA1_WITH_RSA_ENCRYPTION(0x03),            // SHA-1 with RSA Encryption
    SHA224_WITH_RSA_ENCRYPTION(0x04),          // SHA-224 with RSA Encryption
    SHA256_WITH_RSA_ENCRYPTION(0x05),          // SHA-256 with RSA Encryption
    SHA384_WITH_RSA_ENCRYPTION(0x06),          // SHA-384 with RSA Encryption
    SHA512_WITH_RSA_ENCRYPTION(0x07),          // SHA-512 with RSA Encryption
    RSASSA_PSS(0x08),                          // RSASSA-PSS
    DSA_WITH_SHA1(0x09),                       // DSA with SHA-1
    DSA_WITH_SHA224(0x0A),                     // DSA with SHA-224
    DSA_WITH_SHA256(0x0B),                     // DSA with SHA-256
    ECDSA_WITH_SHA1(0x0C),                     // ECDSA with SHA-1
    ECDSA_WITH_SHA224(0x0D),                   // ECDSA with SHA-224
    ECDSA_WITH_SHA256(0x0E),                   // ECDSA with SHA-256
    ECDSA_WITH_SHA384(0x0F),                   // ECDSA with SHA-384
    ECDSA_WITH_SHA512(0x10),                   // ECDSA with SHA-512
    SHA3_256_WITH_RSA_ENCRYPTION(0x11),        // SHA3-256 with RSA Encryption
    SHA3_384_WITH_RSA_ENCRYPTION(0x12),        // SHA3-384 with RSA Encryption
    SHA3_512_WITH_RSA_ENCRYPTION(0x13);        // SHA3-512 with RSA Encryption
    //EXTENSIONS("8XXXXXXX");                          // Extensions for future use

    private final int value;

    /**
     * Constructor for DigitalSignatureAlgorithm.
     *
     * @param value The hex value corresponding to the digital signature algorithm.
     */
    KMIPDigitalSignatureAlgorithm(int value)
    {
        this.value = value;
    }

    /**
     * Gets the hex value associated with the digital signature algorithm.
     *
     * @return The hex value as a String.
     */
    public int getValue()
    {
        return value;
    }

    /**
     * Retrieves a DigitalSignatureAlgorithm based on the provided value.
     *
     * @param value The hex value of the digital signature algorithm.
     * @return The corresponding DigitalSignatureAlgorithm enum.
     * @throws IllegalArgumentException if the value does not match any algorithm.
     */
    public static KMIPDigitalSignatureAlgorithm fromValue(int value)
    {
        for (KMIPDigitalSignatureAlgorithm algorithm : KMIPDigitalSignatureAlgorithm.values())
        {
            if (algorithm.value == value)
            {
                return algorithm;
            }
        }
        throw new IllegalArgumentException("Unknown digital signature algorithm value: " + value);
    }
}

