package org.bouncycastle.crypto.tls;

/**
 * @deprecated Migrate to the (D)TLS API in org.bouncycastle.tls (bctls jar).
 */
public class NameType
{
    /*
     * RFC 3546 3.1.
     */
    public static final short host_name = 0;

    public static boolean isValid(short nameType)
    {
        return nameType == host_name;
    }
}
