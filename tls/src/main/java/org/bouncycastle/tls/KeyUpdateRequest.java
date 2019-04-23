package org.bouncycastle.tls;

/**
 * RFC 8446 4.6.3
 */
public class KeyUpdateRequest
{
    public static final short update_not_requested = 0;
    public static final short update_requested = 1;

    public static String getName(short keyUpdateRequest)
    {
        switch (keyUpdateRequest)
        {
        case update_not_requested:
            return "update_not_requested";
        case update_requested:
            return "update_requested";
        default:
            return "UNKNOWN";
        }
    }

    public static String getText(short keyUpdateRequest)
    {
        return getName(keyUpdateRequest) + "(" + keyUpdateRequest + ")";
    }

    public static boolean isValid(short keyUpdateRequest)
    {
        return keyUpdateRequest >= update_not_requested && keyUpdateRequest <= update_requested;
    }
}
