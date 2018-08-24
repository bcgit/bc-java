package org.bouncycastle.tls;

/**
 * RFC 5246 7.4.1.4.1 (in RFC 2246, there were no specific values assigned)
 */
public class SignatureAlgorithm
{
    public static final short anonymous = 0;
    public static final short rsa = 1;
    public static final short dsa = 2;
    public static final short ecdsa = 3;

    /*
     * RFC 8422
     */
    public static final short ed25519 = 7;
    public static final short ed448 = 8;

    public static String getName(short signatureAlgorithm)
    {
        switch (signatureAlgorithm)
        {
        case anonymous:
            return "anonymous";
        case rsa:
            return "rsa";
        case dsa:
            return "dsa";
        case ecdsa:
            return "ecdsa";
        case ed25519:
            return "ed25519";
        case ed448:
            return "ed448";
        default:
            return "UNKNOWN";
        }
    }

    public static String getText(short signatureAlgorithm)
    {
        return getName(signatureAlgorithm) + "(" + signatureAlgorithm + ")";
    }
}
