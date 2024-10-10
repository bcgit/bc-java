package org.bouncycastle.crypto.split;

/**
 * The CryptographicAlgorithm enum represents various cryptographic algorithms and their corresponding values.
 */
public class KMIPCryptographicAlgorithm
{
    public static final int DES = 0x01;                         // DES
    public static final int TRIPLE_DES = 0x02;                   // 3DES
    public static final int AES = 0x03;                          // AES
    public static final int RSA = 0x04;                          // RSA
    public static final int DSA = 0x05;                          // DSA
    public static final int ECDSA = 0x06;                        // ECDSA
    public static final int HMAC_SHA1 = 0x07;                    // HMAC-SHA1
    public static final int HMAC_SHA224 = 0x08;                  // HMAC-SHA224
    public static final int HMAC_SHA256 = 0x09;                  // HMAC-SHA256
    public static final int HMAC_SHA384 = 0x0A;                  // HMAC-SHA384
    public static final int HMAC_SHA512 = 0x0B;                  // HMAC-SHA512
    public static final int HMAC_MD5 = 0x0C;                     // HMAC-MD5
    public static final int DH = 0x0D;                           // DH (Diffie-Hellman)
    public static final int ECDH = 0x0E;                         // ECDH (Elliptic Curve Diffie-Hellman)
    public static final int ECMQV = 0x0F;                        // ECMQV
    public static final int BLOWFISH = 0x10;                     // Blowfish
    public static final int CAMELLIA = 0x11;                     // Camellia
    public static final int CAST5 = 0x12;                        // CAST5
    public static final int IDEA = 0x13;                         // IDEA
    public static final int MARS = 0x14;                         // MARS
    public static final int RC2 = 0x15;                          // RC2
    public static final int RC4 = 0x16;                          // RC4
    public static final int RC5 = 0x17;                          // RC5
    public static final int SKIPJACK = 0x18;                     // SKIPJACK
    public static final int TWOFISH = 0x19;                      // Twofish
    public static final int EC = 0x1A;                           // EC (Elliptic Curve)
    public static final int ONE_TIME_PAD = 0x1B;                 // One Time Pad
    public static final int CHACHA20 = 0x1C;                     // ChaCha20
    public static final int POLY1305 = 0x1D;                     // Poly1305
    public static final int CHACHA20_POLY1305 = 0x1E;            // ChaCha20Poly1305
    public static final int SHA3_224 = 0x1F;                     // SHA3-224
    public static final int SHA3_256 = 0x20;                     // SHA3-256
    public static final int SHA3_384 = 0x21;                     // SHA3-384
    public static final int SHA3_512 = 0x22;                     // SHA3-512
    public static final int HMAC_SHA3_224 = 0x23;                // HMAC-SHA3-224
    public static final int HMAC_SHA3_256 = 0x24;                // HMAC-SHA3-256
    public static final int HMAC_SHA3_384 = 0x25;                // HMAC-SHA3-384
    public static final int HMAC_SHA3_512 = 0x26;                // HMAC-SHA3-512
    public static final int SHAKE_128 = 0x27;                    // SHAKE-128
    public static final int SHAKE_256 = 0x28;                    // SHAKE-256
    public static final int ARIA = 0x29;                         // ARIA
    public static final int SEED = 0x2A;                         // SEED
    public static final int SM2 = 0x2B;                          // SM2
    public static final int SM3 = 0x2C;                          // SM3
    public static final int SM4 = 0x2D;                          // SM4
    public static final int GOST_R_34_10_2012 = 0x2E;            // GOST R 34.10-2012
    public static final int GOST_R_34_11_2012 = 0x2F;            // GOST R 34.11-2012
    public static final int GOST_R_34_13_2015 = 0x30;            // GOST R 34.13-2015
    public static final int GOST_28147_89 = 0x31;                // GOST 28147-89
    public static final int XMSS = 0x32;                         // XMSS
    public static final int SPHINCS_256 = 0x33;                  // SPHINCS-256
    public static final int MCELIECE = 0x34;                     // McEliece
    public static final int MCELIECE_6960119 = 0x35;             // McEliece-6960119
    public static final int MCELIECE_8192128 = 0x36;             // McEliece-8192128
    public static final int ED25519 = 0x37;                      // Ed25519
    public static final int ED448 = 0x38;                        // Ed448
    //public static final int EXTENSIONS("8XXXXXXX");                   // Extensions for future use
}

