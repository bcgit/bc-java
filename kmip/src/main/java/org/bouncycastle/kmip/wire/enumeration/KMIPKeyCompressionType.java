package org.bouncycastle.kmip.wire.enumeration;

/**
 * Enumeration representing the key compression types for elliptic curve public keys.
 */
public enum KMIPKeyCompressionType
{
    UNCOMPRESSED(0x01),
    COMPRESSED_PRIME(0x02),
    COMPRESSED_CHAR2(0x03),
    HYBRID(0x04);
    //EXTENSIONS("8XXXXXXX");

    private final int value;

    /**
     * Constructor to initialize the enumeration with its value.
     *
     * @param value the string value associated with the key compression type.
     */
    KMIPKeyCompressionType(int value)
    {
        this.value = value;
    }

    /**
     * Returns the string value of the key compression type.
     *
     * @return the string value of the key compression type.
     */
    public int getValue()
    {
        return value;
    }

    /**
     * Returns the KeyCompressionType constant corresponding to the given string value.
     *
     * @param value the string value to find the corresponding KeyCompressionType.
     * @return the KeyCompressionType corresponding to the given value, or null if not found.
     */
    public static KMIPKeyCompressionType fromValue(int value)
    {
        for (KMIPKeyCompressionType kct : KMIPKeyCompressionType.values())
        {
            if (kct.getValue() == value)
            {
                return kct;
            }
        }
        throw new IllegalArgumentException("Unknown key compression type value: " + value);
    }
}
