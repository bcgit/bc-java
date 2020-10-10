package org.bouncycastle.tls;

/**
 * RFC 2246 6.2.1
 */
public class ContentType
{
    public static final short change_cipher_spec = 20;
    public static final short alert = 21;
    public static final short handshake = 22;
    public static final short application_data = 23;
    public static final short heartbeat = 24;

    public static String getName(short contentType)
    {
        switch (contentType)
        {
        case alert:
            return "alert";
        case application_data:
            return "application_data";
        case change_cipher_spec:
            return "change_cipher_spec";
        case handshake:
            return "handshake";
        case heartbeat:
            return "heartbeat";
        default:
            return "UNKNOWN";
        }
    }

    public static String getText(short contentType)
    {
        return getName(contentType) + "(" + contentType + ")";
    }
}
