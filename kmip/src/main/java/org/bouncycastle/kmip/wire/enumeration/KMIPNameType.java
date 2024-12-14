package org.bouncycastle.kmip.wire.enumeration;

/**
 * Enumeration representing the type of a name in the key management system.
 */
public enum KMIPNameType
    implements KMIPEnumeration
{
    UninterpretedTextString(0x00000001),  // Human-readable text not interpreted by the system
    URI(0x00000002);                        // Uniform Resource Identifier

    private final int value;

    /**
     * Constructor for NameType enumeration.
     *
     * @param value The integer (hex) value associated with the name type.
     */
    KMIPNameType(int value)
    {
        this.value = value;
    }

    /**
     * Returns the integer (hex) value associated with the name type.
     *
     * @return The value of the name type.
     */
    public int getValue()
    {
        return value;
    }

    /**
     * Returns the NameType constant corresponding to the given integer value.
     *
     * @param value The integer value of the name type.
     * @return The corresponding NameType constant.
     * @throws IllegalArgumentException if the value does not match any NameType.
     */
    public static KMIPNameType fromValue(int value)
    {
        for (KMIPNameType type : KMIPNameType.values())
        {
            if (type.getValue() == value)
            {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown NameType value: " + value);
    }
}

