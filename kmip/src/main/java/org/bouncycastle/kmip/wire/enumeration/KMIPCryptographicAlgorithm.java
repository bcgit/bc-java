package org.bouncycastle.kmip.wire.enumeration;

/**
 * The CryptographicAlgorithm enum represents various cryptographic algorithms and their corresponding values.
 */
public enum KMIPCryptographicAlgorithm
    implements KMIPEnumeration
{
    DES(0x01),                         // DES
    TRIPLE_DES(0x02),                   // 3DES
    AES(0x03),                          // AES
    RSA(0x04),                          // RSA
    DSA(0x05),                          // DSA
    ECDSA(0x06),                        // ECDSA
    HMAC_SHA1(0x07),                    // HMAC-SHA1
    HMAC_SHA224(0x08),                  // HMAC-SHA224
    HMAC_SHA256(0x09),                  // HMAC-SHA256
    HMAC_SHA384(0x0A),                  // HMAC-SHA384
    HMAC_SHA512(0x0B),                  // HMAC-SHA512
    HMAC_MD5(0x0C),                     // HMAC-MD5
    DH(0x0D),                           // DH (Diffie-Hellman)
    ECDH(0x0E),                         // ECDH (Elliptic Curve Diffie-Hellman)
    ECMQV(0x0F),                        // ECMQV
    Blowfish(0x10),                     // Blowfish
    Camellia(0x11),                     // Camellia
    CAST5(0x12),                        // CAST5
    IDEA(0x13),                         // IDEA
    MARS(0x14),                         // MARS
    RC2(0x15),                          // RC2
    RC4(0x16),                          // RC4
    RC5(0x17),                          // RC5
    SKIPJACK(0x18),                     // SKIPJACK
    Twofish(0x19),                      // Twofish
    EC(0x1A),                           // EC (Elliptic Curve)
    OneTimePad(0x1B),                 // One Time Pad
    ChaCha20(0x1C),                     // ChaCha20
    Poly1305(0x1D),                     // Poly1305
    ChaCha20Poly1305(0x1E),            // ChaCha20Poly1305
    SHA3_224(0x1F),                     // SHA3-224
    SHA3_256(0x20),                     // SHA3-256
    SHA3_384(0x21),                     // SHA3-384
    SHA3_512(0x22),                     // SHA3-512
    HMAC_SHA3_224(0x23),                // HMAC-SHA3-224
    HMAC_SHA3_256(0x24),                // HMAC-SHA3-256
    HMAC_SHA3_384(0x25),                // HMAC-SHA3-384
    HMAC_SHA3_512(0x26),                // HMAC-SHA3-512
    SHAKE_128(0x27),                    // SHAKE-128
    SHAKE_256(0x28),                    // SHAKE-256
    ARIA(0x29),                         // ARIA
    SEED(0x2A),                         // SEED
    SM2(0x2B),                          // SM2
    SM3(0x2C),                          // SM3
    SM4(0x2D),                          // SM4
    GOST_R_34_10_2012(0x2E),            // GOST R 34.10-2012
    GOST_R_34_11_2012(0x2F),            // GOST R 34.11-2012
    GOST_R_34_13_2015(0x30),            // GOST R 34.13-2015
    GOST_28147_89(0x31),                // GOST 28147-89
    XMSS(0x32),                         // XMSS
    SPHINCS_256(0x33),                  // SPHINCS-256
    McEliece(0x34),                     // McEliece
    McEliece_6960119(0x35),             // McEliece-6960119
    McEliece_8192128(0x36),             // McEliece-8192128
    ED25519(0x37),                      // Ed25519
    ED448(0x38);                        // Ed448
    //EXTENSIONS("8XXXXXXX");                   // Extensions for future use

    private final int value;

    /**
     * Constructor for CryptographicAlgorithm.
     *
     * @param value The hex value corresponding to the cryptographic algorithm.
     */
    KMIPCryptographicAlgorithm(int value)
    {
        this.value = value;
    }

    /**
     * Gets the hex value associated with the cryptographic algorithm.
     *
     * @return The hex value as a String.
     */
    public int getValue()
    {
        return value;
    }

    /**
     * Retrieves a CryptographicAlgorithm based on the provided value.
     *
     * @param value The hex value of the cryptographic algorithm.
     * @return The corresponding CryptographicAlgorithm enum.
     * @throws IllegalArgumentException if the value does not match any algorithm.
     */
    public static KMIPCryptographicAlgorithm fromValue(int value)
    {
        for (KMIPCryptographicAlgorithm algorithm : KMIPCryptographicAlgorithm.values())
        {
            if (algorithm.value == value)
            {
                return algorithm;
            }
        }
        throw new IllegalArgumentException("Unknown cryptographic algorithm value: " + value);
    }
}

