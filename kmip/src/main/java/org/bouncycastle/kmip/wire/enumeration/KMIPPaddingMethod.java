package org.bouncycastle.kmip.wire.enumeration;

/**
 * The PaddingMethod enum represents various padding methods used
 * in cryptographic operations.
 */
public enum KMIPPaddingMethod
{

    NONE(0x01),          // No padding
    OAEP(0x02),          // Optimal Asymmetric Encryption Padding
    PKCS5(0x03),         // PKCS#5 Padding
    SSL3(0x04),          // SSL 3.0 Padding
    ZEROS(0x05),         // Padding with zeros
    ANSI_X9_23(0x06),    // ANSI X9.23 Padding
    ISO_10126(0x07),     // ISO 10126 Padding
    PKCS1_V1_5(0x08),    // PKCS#1 v1.5 Padding
    X9_31(0x09),         // X9.31 Padding
    PSS(0x0A);          // Probabilistic Signature Scheme (PSS) Padding
    //EXTENSIONS("8XXXXXXX");    // Extensions for future use

    private final int value;

    /**
     * Constructor for PaddingMethod.
     *
     * @param value The hex value corresponding to the padding method.
     */
    KMIPPaddingMethod(int value)
    {
        this.value = value;
    }

    /**
     * Gets the hex value associated with the padding method.
     *
     * @return The hex value as a String.
     */
    public int getValue()
    {
        return value;
    }

    /**
     * Retrieves a PaddingMethod based on the provided value.
     *
     * @param value The hex value of the padding method.
     * @return The corresponding PaddingMethod enum.
     * @throws IllegalArgumentException if the value does not match any method.
     */
    public static KMIPPaddingMethod fromValue(int value)
    {
        for (KMIPPaddingMethod method : KMIPPaddingMethod.values())
        {
            if (method.value == value)
            {
                return method;
            }
        }
        throw new IllegalArgumentException("Unknown padding method value: " + value);
    }
}

