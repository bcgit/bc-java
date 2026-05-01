package org.bouncycastle.kmip.wire.enumeration;

/**
 * Enumeration representing the mask generators used in cryptographic operations.
 */
public enum KMIPMaskGenerator
{
    MGF1(1);
//    EXTENSIONS("8XXXXXXX");

    private final int value;

    /**
     * Constructor to initialize the enumeration with its value.
     *
     * @param value the string value associated with the mask generator.
     */
    KMIPMaskGenerator(int value)
    {
        this.value = value;
    }

    /**
     * Returns the string value of the mask generator.
     *
     * @return the string value of the mask generator.
     */
    public int getValue()
    {
        return value;
    }

    /**
     * Retrieves a KMIPMaskGenerator based on the provided value.
     *
     * @param value The hex value of the mask generator.
     * @return The corresponding KeyRoleType enum.
     * @throws IllegalArgumentException if the value does not match any role type.
     */
    public static KMIPMaskGenerator fromValue(int value)
    {
        for (KMIPMaskGenerator mg : KMIPMaskGenerator.values())
        {
            if (mg.value == value)
            {
                return mg;
            }
        }
        throw new IllegalArgumentException("Unknown mask generator value: " + value);
    }
}
