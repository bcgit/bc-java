package org.bouncycastle.crypto.split;

/**
 * Enumeration representing the key format types for cryptographic keys.
 */
public enum KMIPKeyFormatType
{
    RAW(0x01),
    OPAQUE(0x02),
    PKCS1(0x03),
    PKCS8(0x04),
    X509(0x05),
    EC_PRIVATE_KEY(0x06),
    TRANSPARENT_SYMMETRIC_KEY(0x07),
    TRANSPARENT_DSA_PRIVATE_KEY(0x08),
    TRANSPARENT_DSA_PUBLIC_KEY(0x09),
    TRANSPARENT_RSA_PRIVATE_KEY(0x0A),
    TRANSPARENT_RSA_PUBLIC_KEY(0x0B),
    TRANSPARENT_DH_PRIVATE_KEY(0x0C),
    TRANSPARENT_DH_PUBLIC_KEY(0x0D),
    RESERVED_1(0x0E),
    RESERVED_2(0x0F),
    RESERVED_3(0x10),
    RESERVED_4(0x11),
    RESERVED_5(0x12),
    RESERVED_6(0x13),
    TRANSPARENT_EC_PRIVATE_KEY(0x14),
    TRANSPARENT_EC_PUBLIC_KEY(0x15),
    PKCS12(0x16),
    PKCS10(0x17);
    //EXTENSIONS("8XXXXXXX");

    private final int value;

    /**
     * Constructor to initialize the enumeration with its value.
     *
     * @param value the string value associated with the key format type.
     */
    KMIPKeyFormatType(int value)
    {
        this.value = value;
    }

    /**
     * Returns the string value of the key format type.
     *
     * @return the string value of the key format type.
     */
    public int getValue()
    {
        return value;
    }

    /**
     * Returns the KeyFormatType constant corresponding to the given string value.
     *
     * @param value the string value to find the corresponding KeyFormatType.
     * @return the KeyFormatType corresponding to the given value, or null if not found.
     */
    public static KMIPKeyFormatType fromValue(int value)
    {
        for (KMIPKeyFormatType kft : KMIPKeyFormatType.values())
        {
            if (kft.getValue() == value)
            {
                return kft;
            }
        }
        throw new IllegalArgumentException("Unknown key format type value: " + value);
    }
}

