package org.bouncycastle.tls;

/**
 * RFC 2246
 * <p>
 * Note that the values here are implementation-specific and arbitrary. It is recommended not to
 * depend on the particular values (e.g. serialization).
 */
public class MACAlgorithm
{
    public static final int _null = 0;
    public static final int md5 = 1;
    public static final int sha = 2;

    /*
     * RFC 5246
     */
    public static final int hmac_md5 = md5;
    public static final int hmac_sha1 = sha;
    public static final int hmac_sha256 = 3;
    public static final int hmac_sha384 = 4;
    public static final int hmac_sha512 = 5;

    public static String getName(int macAlgorithm)
    {
        switch (macAlgorithm)
        {
        case _null:
            return "null";
        case hmac_md5:
            return "hmac_md5";
        case hmac_sha1:
            return "hmac_sha1";
        case hmac_sha256:
            return "hmac_sha256";
        case hmac_sha384:
            return "hmac_sha384";
        case hmac_sha512:
            return "hmac_sha512";
        default:
            return "UNKNOWN";
        }
    }

    public static String getText(int macAlgorithm)
    {
        return getName(macAlgorithm) + "(" + macAlgorithm + ")";
    }

    public static boolean isHMAC(int macAlgorithm)
    {
        switch (macAlgorithm)
        {
        case hmac_md5:
        case hmac_sha1:
        case hmac_sha256:
        case hmac_sha384:
        case hmac_sha512:
            return true;
        default:
            return false;
        }
    }
}
