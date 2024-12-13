package org.bouncycastle.kmip.wire.enumeration;

public enum KMIPSecretDataType
{
    Password(0x00000001),

    Seed(0x00000002);

    private final int value;

    KMIPSecretDataType(int value)
    {
        this.value = value;
    }

    public int getValue()
    {
        return value;
    }

    public static KMIPSecretDataType fromValue(int value)
    {
        for (KMIPSecretDataType type : KMIPSecretDataType.values())
        {
            if (type.getValue() == value)
            {
                return type;
            }
        }
        throw new IllegalArgumentException("No SecretDataType found for value: " + value);
    }
}
