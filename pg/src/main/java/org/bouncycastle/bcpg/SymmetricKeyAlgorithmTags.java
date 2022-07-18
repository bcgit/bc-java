package org.bouncycastle.bcpg;

/**
 * Basic tags for symmetric key algorithms
 */
public interface SymmetricKeyAlgorithmTags 
{
    int NULL = 0;        // Plaintext or unencrypted data
    int IDEA = 1;        // IDEA [IDEA]
    int TRIPLE_DES = 2;  // Triple-DES (DES-EDE, as per spec -168 bit key derived from 192)
    int CAST5 = 3;       // CAST5 (128 bit key, as per RFC 2144)
    int BLOWFISH = 4;    // Blowfish (128 bit key, 16 rounds) [BLOWFISH]
    int SAFER = 5;       // SAFER-SK128 (13 rounds) [SAFER]
    int DES = 6;         // Reserved for DES/SK
    int AES_128 = 7;     // Reserved for AES with 128-bit key
    int AES_192 = 8;     // Reserved for AES with 192-bit key
    int AES_256 = 9;     // Reserved for AES with 256-bit key
    int TWOFISH = 10;    // Reserved for Twofish
    int CAMELLIA_128 = 11;    // Reserved for Camellia with 128-bit key
    int CAMELLIA_192 = 12;    // Reserved for Camellia with 192-bit key
    int CAMELLIA_256 = 13;    // Reserved for Camellia with 256-bit key
}
