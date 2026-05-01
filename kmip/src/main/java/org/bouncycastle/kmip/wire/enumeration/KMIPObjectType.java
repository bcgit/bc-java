package org.bouncycastle.kmip.wire.enumeration;

/**
 * Enumeration of Object Types.
 */
public enum KMIPObjectType
    implements KMIPEnumeration
{
    Certificate(0x01),
    SymmetricKey(0x02),
    PublicKey(0x03),
    PrivateKey(0x04),
    SplitKey(0x05),
    Reserved(0x06),
    SecretData(0x07),
    OpaqueObject(0x08),
    PgpKey(0x09),
    CertificateRequest(0x0A);

    private final int value;

    KMIPObjectType(int value)
    {
        this.value = value;
    }

    public int getValue()
    {
        return value;
    }

    /**
     * Returns the ObjectType corresponding to the given value.
     *
     * @param value the integer value of the ObjectType
     * @return the corresponding ObjectType
     * @throws IllegalArgumentException if the value does not correspond to any ObjectType
     */
    public static KMIPObjectType fromValue(int value)
    {
        for (KMIPObjectType type : KMIPObjectType.values())
        {
            if (type.getValue() == value)
            {
                return type;
            }
        }
        throw new IllegalArgumentException("No ObjectType found for value: " + value);
    }
}

