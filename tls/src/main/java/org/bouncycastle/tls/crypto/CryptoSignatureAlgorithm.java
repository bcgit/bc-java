package org.bouncycastle.tls.crypto;

public abstract class CryptoSignatureAlgorithm
{
    public static final int rsa = 1;
    public static final int dsa = 2;
    public static final int ecdsa = 3;
    public static final int rsa_pss_rsae_sha256 = 4;
    public static final int rsa_pss_rsae_sha384 = 5;
    public static final int rsa_pss_rsae_sha512 = 6;
    public static final int ed25519 = 7;
    public static final int ed448 = 8;
    public static final int rsa_pss_pss_sha256 = 9;
    public static final int rsa_pss_pss_sha384 = 10;
    public static final int rsa_pss_pss_sha512 = 11;
    public static final int gostr34102012_256 = 64;
    public static final int gostr34102012_512 = 65;
    public static final int sm2 = 200;
}
