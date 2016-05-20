package org.bouncycastle.crypto.tls;

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
