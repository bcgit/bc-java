package org.bouncycastle.kmip.wire.enumeration;

/**
 * Enum representing the Encoding Option Enumeration.
 * <p>
 * This enum defines the available encoding options for cryptographic key materials.
 * Each option corresponds to a specific value that can be used in the context of
 * key management operations.
 * </p>
 */
public enum KMIPEncodingOption
{

    /**
     * Represents no encoding, indicating that the wrapped
     * un-encoded value of the Byte String Key Material field
     * is to be used.
     */
    NO_ENCODING(1),

    /**
     * Represents TTLV encoding, indicating that the wrapped
     * TTLV-encoded Key Value structure is to be used.
     */
    NTTLV_ENCODING(2);

    //EXTENSIONS("8XXXXXXX");
    private final int value;

    KMIPEncodingOption(int value)
    {
        this.value = value;
    }

    public int getValue()
    {
        return value;
    }

    public static KMIPEncodingOption fromValue(int value)
    {
        for (KMIPEncodingOption algorithm : KMIPEncodingOption.values())
        {
            if (algorithm.value == value)
            {
                return algorithm;
            }
        }
        throw new IllegalArgumentException("Unknown encoding option value: " + value);
    }
}

