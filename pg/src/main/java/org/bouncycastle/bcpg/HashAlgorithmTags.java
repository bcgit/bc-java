package org.bouncycastle.bcpg;

/**
 * basic tags for hash algorithms
 */
public interface HashAlgorithmTags 
{
    int MD5 = 1;          // MD5
    int SHA1 = 2;         // SHA-1
    int RIPEMD160 = 3;    // RIPE-MD/160
    int DOUBLE_SHA = 4;   // Reserved for double-width SHA (experimental)
    int MD2 = 5;          // MD2
    int TIGER_192 = 6;    // Reserved for TIGER/192
    int HAVAL_5_160 = 7;  // Reserved for HAVAL (5 pass, 160-bit)
    
    int SHA256 = 8;       // SHA-256
    int SHA384 = 9;       // SHA-384
    int SHA512 = 10;      // SHA-512
    int SHA224 = 11;      // SHA-224
    int SHA3_256 = 12;    // SHA3-256
    int SHA3_512 = 14;    // SHA3-512

    int MD4 = 301;
    int SHA3_224 = 312; // SHA3-224
    int SHA3_256_OLD = 313; //SHA3-256
    int SHA3_384 = 314; // SHA3-384
    int SHA3_512_OLD = 315; // SHA3-512


    int SM3 = 326; // SM3

}
