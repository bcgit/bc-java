package org.bouncycastle.crypto.split;
/**
 * Enumeration of Object Types.
 */
public enum ObjectTypeEnum {
    CERTIFICATE(0x00000001),
    SYMMETRIC_KEY(0x00000002),
    PUBLIC_KEY(0x00000003),
    PRIVATE_KEY(0x00000004),
    SPLIT_KEY(0x00000005),
    RESERVED(0x00000006),
    SECRET_DATA(0x00000007),
    OPAQUE_OBJECT(0x00000008),
    PGP_KEY(0x00000009),
    CERTIFICATE_REQUEST(0x0000000A);

    private final int value;

    ObjectTypeEnum(int value) {
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
    public static ObjectTypeEnum fromValue(int value) {
        for (ObjectTypeEnum type : ObjectTypeEnum.values()) {
            if (type.getValue() == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("No ObjectType found for value: " + value);
    }
}

