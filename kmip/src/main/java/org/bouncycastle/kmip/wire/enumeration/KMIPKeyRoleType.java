package org.bouncycastle.kmip.wire.enumeration;

/**
 * The KeyRoleType enum represents various roles a cryptographic key can take in cryptographic operations.
 * <p>
 * Note that while the set and definitions of key role types are chosen to match [X9 TR-31](ANSI, X9 TR-31: Interoperable
 * Secure Key Exchange Key Block Specification for Symmetric Algorithms, 2010.) there is no necessity to match binary
 * representations.
 */
public enum KMIPKeyRoleType
{
    BDK(0x01),              // Base Derivation Key
    CVK(0x02),              // Card Verification Key
    DEK(0x03),              // Data Encryption Key
    MKAC(0x04),             // Master Key Application Cryptogram
    MKSMC(0x05),            // Master Key Secure Messaging - Confidentiality
    MKSMI(0x06),            // Master Key Secure Messaging - Integrity
    MKDAC(0x07),            // Master Key Dynamic Authentication Cryptogram
    MKDN(0x08),             // Master Key Data Network
    MKCP(0x09),             // Master Key Common Platform
    MKOTH(0x0A),            // Master Key Other
    KEK(0x0B),              // Key Encryption Key
    MAC16609(0x0C),         // MAC Key for ANSI X9.24 Part 1: 2009
    MAC97971(0x0D),         // MAC Key for ISO 9797-1: 2011 MAC Algorithm 1
    MAC97972(0x0E),         // MAC Key for ISO 9797-1: 2011 MAC Algorithm 2
    MAC97973(0x0F),         // MAC Key for ISO 9797-1: 2011 MAC Algorithm 3
    MAC97974(0x10),         // MAC Key for ISO 9797-1: 2011 MAC Algorithm 4
    MAC97975(0x11),         // MAC Key for ISO 9797-1: 2011 MAC Algorithm 5
    ZPK(0x12),              // Zone PIN Key
    PVKIBM(0x13),           // PIN Verification Key - IBM
    PVKPVV(0x14),           // PIN Verification Key - PVV
    PVKOTH(0x15),           // PIN Verification Key - Other
    DUKPT(0x16),            // Derived Unique Key Per Transaction
    IV(0x17),               // Initialization Vector
    TRKBK(0x18);            // Track Block Key
    //EXTENSIONS("8XXXXXXX");       // Extensions for future use

    private final int value;

    /**
     * Constructor for KeyRoleType.
     *
     * @param value The hex value corresponding to the key role type.
     */
    KMIPKeyRoleType(int value)
    {
        this.value = value;
    }

    /**
     * Gets the hex value associated with the key role type.
     *
     * @return The hex value as a String.
     */
    public int getValue()
    {
        return value;
    }

    /**
     * Retrieves a KeyRoleType based on the provided value.
     *
     * @param value The hex value of the key role type.
     * @return The corresponding KeyRoleType enum.
     * @throws IllegalArgumentException if the value does not match any role type.
     */
    public static KMIPKeyRoleType fromValue(int value)
    {
        for (KMIPKeyRoleType role : KMIPKeyRoleType.values())
        {
            if (role.value == value)
            {
                return role;
            }
        }
        throw new IllegalArgumentException("Unknown key role type value: " + value);
    }
}


