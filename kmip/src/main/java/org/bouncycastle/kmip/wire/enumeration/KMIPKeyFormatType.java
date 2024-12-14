package org.bouncycastle.kmip.wire.enumeration;

/**
 * Enumeration representing the key format types for cryptographic keys.
 */
public enum KMIPKeyFormatType
    implements KMIPEnumeration
{
    Raw(0x01),
    Opaque(0x02),
    PKCS1(0x03),
    PKCS8(0x04),
    X509(0x05),
    ECPrivateKey(0x06),
    TransparentSymmetricKey(0x07),
    TransparentDSAPrivateKey(0x08),
    TransparentDSAPublicKey(0x09),
    TransparentRSAPrivateKey(0x0A),
    TransparentRSAPublicKey(0x0B),
    TransparentDHPrivateKey(0x0C),
    TransparentDHPublicKey(0x0D),
    TransparentECPrivateKey(0x14),
    TransparentECPublicKey(0x15),
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

