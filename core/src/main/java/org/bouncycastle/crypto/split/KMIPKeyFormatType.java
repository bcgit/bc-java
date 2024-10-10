package org.bouncycastle.crypto.split;

/**
 * Enumeration representing the key format types for cryptographic keys.
 */
public class KMIPKeyFormatType
{
    public static final int RAW = 0x01;
    public static final int OPAQUE = 0x02;
    public static final int PKCS1 = 0x03;
    public static final int PKCS8 = 0x04;
    public static final int X509 = 0x05;
    public static final int EC_PRIVATE_KEY = 0x06;
    public static final int TRANSPARENT_SYMMETRIC_KEY = 0x07;
    public static final int TRANSPARENT_DSA_PRIVATE_KEY = 0x08;
    public static final int TRANSPARENT_DSA_PUBLIC_KEY = 0x09;
    public static final int TRANSPARENT_RSA_PRIVATE_KEY = 0x0A;
    public static final int TRANSPARENT_RSA_PUBLIC_KEY = 0x0B;
    public static final int TRANSPARENT_DH_PRIVATE_KEY = 0x0C;
    public static final int TRANSPARENT_DH_PUBLIC_KEY = 0x0D;
    public static final int RESERVED_1 = 0x0E;
    public static final int RESERVED_2 = 0x0F;
    public static final int RESERVED_3 = 0x10;
    public static final int RESERVED_4 = 0x11;
    public static final int RESERVED_5 = 0x12;
    public static final int RESERVED_6 = 0x13;
    public static final int TRANSPARENT_EC_PRIVATE_KEY = 0x14;
    public static final int TRANSPARENT_EC_PUBLIC_KEY = 0x15;
    public static final int PKCS12 = 0x16;
    public static final int PKCS10 = 0x17;
    //EXTENSIONS("8XXXXXXX");
}

