package org.bouncycastle.crypto.tls;

/**
 * RFC 5246 7.2
 */
public class AlertLevel
{
    public static final short warning = 1;
    public static final short fatal = 2;

    public static String getName(short alertDescription)
    {
        switch (alertDescription)
        {
        case warning:
            return "warning";
        case fatal:
            return "fatal";
        default:
            return "UNKNOWN";
        }
    }

    public static String getText(short alertDescription)
    {
        return getName(alertDescription) + "(" + alertDescription + ")";
    }
}
