package org.bouncycastle.bcpg;

/**
 * basic tags for hash algorithms
 */
public interface HashAlgorithmTags 
{
    public static final int MD5 = 1;          // MD5
    public static final int SHA1 = 2;         // SHA-1
    public static final int RIPEMD160 = 3;    // RIPE-MD/160
    public static final int DOUBLE_SHA = 4;   // Reserved for double-width SHA (experimental)
    public static final int MD2 = 5;          // MD2
    public static final int TIGER_192 = 6;    // Reserved for TIGER/192
    public static final int HAVAL_5_160 = 7;  // Reserved for HAVAL (5 pass, 160-bit)
    
    public static final int SHA256 = 8;       // SHA-256
    public static final int SHA384 = 9;       // SHA-384
    public static final int SHA512 = 10;      // SHA-512
    public static final int SHA224 = 11;      // SHA-224
    public static final int SHA3_256 = 12;    // SHA3-256
    public static final int SHA3_512 = 14;    // SHA3-512

    public static final int MD4 = 301;
    public static final int SHA3_224 = 312; // SHA3-224
    public static final int SHA3_256_OLD = 313; //SHA3-256
    public static final int SHA3_384 = 314; // SHA3-384
    public static final int SHA3_512_OLD = 315; // SHA3-512


    public static final int SM3 = 326; // SM3

}
