package org.bouncycastle.crypto.split;

/**
 * The PaddingMethod enum represents various padding methods used
 * in cryptographic operations.
 */
public enum PaddingMethod {

    NONE("00000001"),          // No padding
    OAEP("00000002"),          // Optimal Asymmetric Encryption Padding
    PKCS5("00000003"),         // PKCS#5 Padding
    SSL3("00000004"),          // SSL 3.0 Padding
    ZEROS("00000005"),         // Padding with zeros
    ANSI_X9_23("00000006"),    // ANSI X9.23 Padding
    ISO_10126("00000007"),     // ISO 10126 Padding
    PKCS1_V1_5("00000008"),    // PKCS#1 v1.5 Padding
    X9_31("00000009"),         // X9.31 Padding
    PSS("0000000A"),           // Probabilistic Signature Scheme (PSS) Padding
    EXTENSIONS("8XXXXXXX");    // Extensions for future use

    private final String value;

    /**
     * Constructor for PaddingMethod.
     *
     * @param value The hex value corresponding to the padding method.
     */
    PaddingMethod(String value) {
        this.value = value;
    }

    /**
     * Gets the hex value associated with the padding method.
     *
     * @return The hex value as a String.
     */
    public String getValue() {
        return value;
    }

    /**
     * Retrieves a PaddingMethod based on the provided value.
     *
     * @param value The hex value of the padding method.
     * @return The corresponding PaddingMethod enum.
     * @throws IllegalArgumentException if the value does not match any method.
     */
    public static PaddingMethod fromValue(String value) {
        for (PaddingMethod method : PaddingMethod.values()) {
            if (method.value.equals(value)) {
                return method;
            }
        }
        throw new IllegalArgumentException("Unknown padding method value: " + value);
    }
}

