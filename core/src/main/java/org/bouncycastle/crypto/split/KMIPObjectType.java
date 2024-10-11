package org.bouncycastle.crypto.split;
/**
 * Enumeration of Object Types.
 */
public enum KMIPObjectType
{
    CERTIFICATE(0x01),
    SYMMETRIC_KEY(0x02),
    PUBLIC_KEY(0x03),
    PRIVATE_KEY(0x04),
    SPLIT_KEY(0x05),
    RESERVED(0x06),
    SECRET_DATA(0x07),
    OPAQUE_OBJECT(0x08),
    PGP_KEY(0x09),
    CERTIFICATE_REQUEST(0x0A);

    private final int value;

    KMIPObjectType(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    /**
     * Returns the ObjectType corresponding to the given value.
     *
     * @param value the integer value of the ObjectType
     * @return the corresponding ObjectType
     * @throws IllegalArgumentException if the value does not correspond to any ObjectType
     */
    public static KMIPObjectType fromValue(int value) {
        for (KMIPObjectType type : KMIPObjectType.values()) {
            if (type.getValue() == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("No ObjectType found for value: " + value);
    }
}

