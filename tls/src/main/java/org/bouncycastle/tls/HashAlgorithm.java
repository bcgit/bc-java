package org.bouncycastle.crypto.tls;

/**
 * RFC 5246 7.4.1.4.1
 */
public class HashAlgorithm
{
    public static final short none = 0;
    public static final short md5 = 1;
    public static final short sha1 = 2;
    public static final short sha224 = 3;
    public static final short sha256 = 4;
    public static final short sha384 = 5;
    public static final short sha512 = 6;

    public static String getName(short hashAlgorithm)
    {
        switch (hashAlgorithm)
        {
        case none:
            return "none";
        case md5:
            return "md5";
        case sha1:
            return "sha1";
        case sha224:
            return "sha224";
        case sha256:
            return "sha256";
        case sha384:
            return "sha384";
        case sha512:
            return "sha512";
        default:
            return "UNKNOWN";
        }
    }

    public static String getText(short hashAlgorithm)
    {
        return getName(hashAlgorithm) + "(" + hashAlgorithm + ")";
    }

    public static boolean isPrivate(short hashAlgorithm)
    {
        return 224 <= hashAlgorithm && hashAlgorithm <= 255; 
    }
}
