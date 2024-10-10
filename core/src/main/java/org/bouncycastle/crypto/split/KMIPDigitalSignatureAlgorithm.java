package org.bouncycastle.crypto.split;

/**
 * The DigitalSignatureAlgorithm enum represents various algorithms used for digital signatures.
 */
public class KMIPDigitalSignatureAlgorithm
{
    public static final int MD2_WITH_RSA_ENCRYPTION = 0x01;             // MD2 with RSA Encryption
    public static final int NMD5_WITH_RSA_ENCRYPTION = 0x02;             // MD5 with RSA Encryption
    public static final int SHA1_WITH_RSA_ENCRYPTION = 0x03;            // SHA-1 with RSA Encryption
    public static final int SHA224_WITH_RSA_ENCRYPTION = 0x04;          // SHA-224 with RSA Encryption
    public static final int SHA256_WITH_RSA_ENCRYPTION = 0x05;          // SHA-256 with RSA Encryption
    public static final int SHA384_WITH_RSA_ENCRYPTION = 0x06;          // SHA-384 with RSA Encryption
    public static final int SHA512_WITH_RSA_ENCRYPTION = 0x07;          // SHA-512 with RSA Encryption
    public static final int RSASSA_PSS = 0x08;                          // RSASSA-PSS
    public static final int DSA_WITH_SHA1 = 0x09;                       // DSA with SHA-1
    public static final int DSA_WITH_SHA224 = 0x0A;                     // DSA with SHA-224
    public static final int DSA_WITH_SHA256 = 0x0B;                     // DSA with SHA-256
    public static final int ECDSA_WITH_SHA1 = 0x0C;                     // ECDSA with SHA-1
    public static final int ECDSA_WITH_SHA224 = 0x0D;                   // ECDSA with SHA-224
    public static final int ECDSA_WITH_SHA256 = 0x0E;                   // ECDSA with SHA-256
    public static final int ECDSA_WITH_SHA384 = 0x0F;                   // ECDSA with SHA-384
    public static final int ECDSA_WITH_SHA512 = 0x10;                   // ECDSA with SHA-512
    public static final int SHA3_256_WITH_RSA_ENCRYPTION = 0x11;        // SHA3-256 with RSA Encryption
    public static final int SHA3_384_WITH_RSA_ENCRYPTION = 0x12;        // SHA3-384 with RSA Encryption
    public static final int SHA3_512_WITH_RSA_ENCRYPTION = 0x13;        // SHA3-512 with RSA Encryption
    //EXTENSIONS("8XXXXXXX");                          // Extensions for future use
}

