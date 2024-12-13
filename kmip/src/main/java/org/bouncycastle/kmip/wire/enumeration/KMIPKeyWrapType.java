package org.bouncycastle.kmip.wire.enumeration;

public enum KMIPKeyWrapType
{
    NotWrapped(0x00000001),
    AsRegistered(0x00000002);

    private final int value;

    /**
     * Constructor for Key Wrap Type enumeration.
     *
     * @param value The integer (hex) value associated with the name type.
     */
    KMIPKeyWrapType(int value)
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
     * Returns the Key Wrap Type constant corresponding to the given integer value.
     *
     * @param value The integer value of the Key Wrap Type.
     * @return The corresponding NameType constant.
     * @throws IllegalArgumentException if the value does not match any Key Wrap Type.
     */
    public static KMIPKeyWrapType fromValue(int value)
    {
        for (KMIPKeyWrapType type : KMIPKeyWrapType.values())
        {
            if (type.getValue() == value)
            {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown NameType value: " + value);
    }
}
