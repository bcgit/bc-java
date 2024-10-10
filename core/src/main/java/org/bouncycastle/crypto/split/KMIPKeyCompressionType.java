package org.bouncycastle.crypto.split;

/**
 * Enumeration representing the key compression types for elliptic curve public keys.
 */
public class KMIPKeyCompressionType
{
    public static final int UNCOMPRESSED = 0x01;
    public static final int COMPRESSED_PRIME = 0x02;
    public static final int COMPRESSED_CHAR2 = 0x03;
    public static final int HYBRID = 0x04;
    //EXTENSIONS("8XXXXXXX");
}

