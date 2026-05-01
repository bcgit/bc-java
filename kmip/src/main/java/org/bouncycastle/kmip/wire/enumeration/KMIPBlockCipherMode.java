package org.bouncycastle.kmip.wire.enumeration;

/**
 * The BlockCipherMode enum represents various block cipher modes that can be used
 * in cryptographic operations.
 */
public enum KMIPBlockCipherMode
{

    CBC(1),        // Cipher Block Chaining
    ECB(2),        // Electronic Codebook
    PCBC(3),       // Propagating Cipher Block Chaining
    CFB(4),        // Cipher Feedback
    OFB(5),        // Output Feedback
    CTR(6),        // Counter
    CMAC(7),       // Cipher-based Message Authentication Code
    CCM(8),        // Counter with CBC-MAC
    GCM(9),        // Galois/Counter Mode
    CBC_MAC(10),    // Cipher Block Chaining - Message Authentication Code
    XTS(11),        // XEX-based Tweaked Codebook Mode with Ciphertext Stealing
    AESKeyWrapPadding(12), // AES Key Wrap with Padding
    NISTKeyWrap(13),      // NIST Key Wrap
    X9_102_AESKW(14),     // X9.102 AES Key Wrap
    X9_102_TDKW(15),      // X9.102 Tweakable Block Cipher Key Wrap
    X9_102_AKW1(16),      // X9.102 AKW1
    X9_102_AKW2(17),      // X9.102 AKW2
    AEAD(18);       // Authenticated Encryption with Associated Data
    //EXTENSIONS("8XXXXXXX");  // Extensions for future use

    private final int value;

    /**
     * Constructor for BlockCipherMode.
     *
     * @param value The hex value corresponding to the block cipher mode.
     */
    KMIPBlockCipherMode(int value)
    {
        this.value = value;
    }

    /**
     * Gets the hex value associated with the block cipher mode.
     *
     * @return The hex value as a String.
     */
    public int getValue()
    {
        return value;
    }

    /**
     * Retrieves a BlockCipherMode based on the provided value.
     *
     * @param value The hex value of the block cipher mode.
     * @return The corresponding BlockCipherMode enum.
     * @throws IllegalArgumentException if the value does not match any mode.
     */
    public static KMIPBlockCipherMode fromValue(int value)
    {
        for (KMIPBlockCipherMode mode : KMIPBlockCipherMode.values())
        {
            if (mode.value == value)
            {
                return mode;
            }
        }
        throw new IllegalArgumentException("Unknown block cipher mode value: " + value);
    }
}

