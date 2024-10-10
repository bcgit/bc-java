package org.bouncycastle.crypto.split;

/**
 * The BlockCipherMode enum represents various block cipher modes that can be used
 * in cryptographic operations.
 */
public class KMIPBlockCipherMode
{

    public static final int CBC = 1;        // Cipher Block Chaining

    public static final int ECB= 2;       // Electronic Codebook

    public static final int PCBC = 3;       // Propagating Cipher Block Chaining

    public static final int CFB = 4;        // Cipher Feedback

    public static final int OFB = 5;        // Output Feedback

    public static final int CTR = 6;        // Counter

    public static final int CMAC = 7;       // Cipher-based Message Authentication Code

    public static final int CCM = 8;        // Counter with CBC-MAC

    public static final int GCM = 9;        // Galois/Counter Mode

    public static final int CBC_MAC = 0x0a;    // Cipher Block Chaining - Message Authentication Code

    public static final int XTS = 0x0b;        // XEX-based Tweaked Codebook Mode with Ciphertext Stealing

    public static final int AESKeyWrapPadding = 0xc0; // AES Key Wrap with Padding

    public static final int NISTKeyWrap = 0x0d;      // NIST Key Wrap

    public static final int X9_102_AESKW = 0x0e;     // X9.102 AES Key Wrap

    public static final int X9_102_TDKW = 0x0F;      // X9.102 Tweakable Block Cipher Key Wrap

    public static final int X9_102_AKW1 = 0x10;      // X9.102 AKW1

    public static final int X9_102_AKW2 = 0x11;      // X9.102 AKW2

    public static final int AEAD = 0x12;        // Authenticated Encryption with Associated Data

    //EXTENSIONS("8XXXXXXX");  // Extensions for future use
}

