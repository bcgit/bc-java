package org.bouncycastle.tls;

/**
 * RFC 6066
 */
public class IdentifierType
{
    public static final short pre_agreed = 0;
    public static final short key_sha1_hash = 1;
    public static final short x509_name = 2;
    public static final short cert_sha1_hash = 3;

    public static String getName(short identifierType)
    {
        switch (identifierType)
        {
        case pre_agreed:
            return "pre_agreed";
        case key_sha1_hash:
            return "key_sha1_hash";
        case x509_name:
            return "x509_name";
        case cert_sha1_hash:
            return "cert_sha1_hash";
        default:
            return "UNKNOWN";
        }
    }
}
