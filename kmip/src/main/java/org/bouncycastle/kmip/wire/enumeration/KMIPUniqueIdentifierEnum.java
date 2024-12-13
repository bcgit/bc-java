package org.bouncycastle.kmip.wire.enumeration;

public enum KMIPUniqueIdentifierEnum
    implements KMIPEnumeration
{
    IDPlaceholder(0x00000001),
    Certify(0x00000002),
    Create(0x00000003),
    CreateKeyPair(0x00000004),
    CreateKeyPairPrivateKey(0x00000005),
    CreateKeyPairPublicKey(0x00000006),
    Create_Split_Key(0x00000007),
    DeriveKey(0x00000008),
    Import(0x00000009),
    Join_Split_Key(0x0000000A),
    Locate(0x0000000B),
    Register(0x0000000C),
    Re_Key(0x0000000D),
    Re_Certify(0x0000000E),
    Re_KeyKeyPair(0x0000000F),
    Re_KeyKeyPairPrivateKey(0x00000010),
    Re_KeyKeyPairPublicKey(0x00000011);

    private final int value;

    /**
     * Constructor for UniqueIdentifierEnum.
     *
     * @param value The hex value representing the unique identifier.
     */
    KMIPUniqueIdentifierEnum(int value)
    {
        this.value = value;
    }

    /**
     * Gets the integer value of the enum.
     *
     * @return The hex value as an integer.
     */
    public int getValue()
    {
        return value;
    }

    /**
     * Retrieves the UniqueIdentifierEnum based on the provided value.
     *
     * @param value The hex value of the unique identifier.
     * @return The corresponding UniqueIdentifierEnum.
     * @throws IllegalArgumentException if the value does not match any enum.
     */
    public static KMIPUniqueIdentifierEnum fromValue(int value)
    {
        for (KMIPUniqueIdentifierEnum identifier : KMIPUniqueIdentifierEnum.values())
        {
            if (identifier.value == value)
            {
                return identifier;
            }
        }
        throw new IllegalArgumentException("Unknown Unique Identifier value: " + value);
    }
}
