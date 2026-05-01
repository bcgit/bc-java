package org.bouncycastle.kmip.wire.enumeration;

/**
 * The HashingAlgorithm enum represents various hashing algorithms
 * used in cryptographic operations.
 */
public enum KMIPHashingAlgorithm
{

    MD2(0x01),           // MD2 hashing algorithm
    MD4(0x02),           // MD4 hashing algorithm
    MD5(0x03),           // MD5 hashing algorithm
    SHA_1(0x04),         // SHA-1 hashing algorithm
    SHA_224(0x05),       // SHA-224 hashing algorithm
    SHA_256(0x06),       // SHA-256 hashing algorithm
    SHA_384(0x07),       // SHA-384 hashing algorithm
    SHA_512(0x08),       // SHA-512 hashing algorithm
    RIPEMD_160(0x09),    // RIPEMD-160 hashing algorithm
    TIGER(0x0A),         // Tiger hashing algorithm
    WHIRLPOOL(0x0B),     // Whirlpool hashing algorithm
    SHA_512_224(0x0C),   // SHA-512/224 hashing algorithm
    SHA_512_256(0x0D),   // SHA-512/256 hashing algorithm
    SHA3_224(0x0E),      // SHA3-224 hashing algorithm
    SHA3_256(0x0F),      // SHA3-256 hashing algorithm
    SHA3_384(0x10),      // SHA3-384 hashing algorithm
    SHA3_512(0x11);      // SHA3-512 hashing algorithm
    //EXTENSIONS("8XXXXXXX");    // Extensions for future use

    private final int value;

    /**
     * Constructor for HashingAlgorithm.
     *
     * @param value The hex value corresponding to the hashing algorithm.
     */
    KMIPHashingAlgorithm(int value)
    {
        this.value = value;
    }

    /**
     * Gets the hex value associated with the hashing algorithm.
     *
     * @return The hex value as a String.
     */
    public int getValue()
    {
        return value;
    }

    /**
     * Retrieves a HashingAlgorithm based on the provided value.
     *
     * @param value The hex value of the hashing algorithm.
     * @return The corresponding HashingAlgorithm enum.
     * @throws IllegalArgumentException if the value does not match any algorithm.
     */
    public static KMIPHashingAlgorithm fromValue(int value)
    {
        for (KMIPHashingAlgorithm algorithm : KMIPHashingAlgorithm.values())
        {
            if (algorithm.value == value)
            {
                return algorithm;
            }
        }
        throw new IllegalArgumentException("Unknown hashing algorithm value: " + value);
    }
}


