package org.bouncycastle.crypto.split;

/**
 * The KeyRoleType enum represents various roles a cryptographic key can take in cryptographic operations.
 * <p>
 * Note that while the set and definitions of key role types are chosen to match [X9 TR-31](ANSI, X9 TR-31: Interoperable
 * Secure Key Exchange Key Block Specification for Symmetric Algorithms, 2010.) there is no necessity to match binary
 * representations.
 */
public class KMIPKeyRoleType
{
    public static final int BDK = 0x01;              // Base Derivation Key
    public static final int CVK = 0x02;              // Card Verification Key
    public static final int DEK = 0x03;              // Data Encryption Key
    public static final int MKAC = 0x04;             // Master Key Application Cryptogram
    public static final int MKSMC = 0x05;            // Master Key Secure Messaging - Confidentiality
    public static final int MKSMI = 0x06;            // Master Key Secure Messaging - Integrity
    public static final int MKDAC = 0x07;            // Master Key Dynamic Authentication Cryptogram
    public static final int MKDN = 0x08;             // Master Key Data Network
    public static final int MKCP = 0x09;             // Master Key Common Platform
    public static final int MKOTH = 0x0A;            // Master Key Other
    public static final int KEK = 0x0B;              // Key Encryption Key
    public static final int MAC16609 = 0x0C;         // MAC Key for ANSI X9.24 Part 1: 2009
    public static final int MAC97971 = 0x0D;         // MAC Key for ISO 9797-1: 2011 MAC Algorithm 1
    public static final int MAC97972 = 0x0E;         // MAC Key for ISO 9797-1: 2011 MAC Algorithm 2
    public static final int MAC97973 = 0x0F;         // MAC Key for ISO 9797-1: 2011 MAC Algorithm 3
    public static final int MAC97974 = 0x10;         // MAC Key for ISO 9797-1: 2011 MAC Algorithm 4
    public static final int MAC97975 = 0x11;         // MAC Key for ISO 9797-1: 2011 MAC Algorithm 5
    public static final int ZPK = 0x12;              // Zone PIN Key
    public static final int PVKIBM = 0x13;           // PIN Verification Key - IBM
    public static final int PVKPVV = 0x14;           // PIN Verification Key - PVV
    public static final int PVKOTH = 0x15;           // PIN Verification Key - Other
    public static final int DUKPT = 0x16;            // Derived Unique Key Per Transaction
    public static final int IV = 0x17;               // Initialization Vector
    public static final int TRKBK = 0x18;            // Track Block Key
    //EXTENSIONS("8XXXXXXX");       // Extensions for future use
}

