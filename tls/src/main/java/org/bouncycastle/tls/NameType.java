package org.bouncycastle.tls;

public class NameType
{
    /*
     * RFC 3546 3.1.
     */
    public static final short host_name = 0;

    public static String getName(short nameType)
    {
        switch (nameType)
        {
        case host_name:
            return "host_name";
        default:
            return "UNKNOWN";
        }
    }

    public static String getText(short nameType)
    {
        return getName(nameType) + "(" + nameType + ")";
    }

    public static boolean isRecognized(short nameType)
    {
        return host_name == nameType;
    }

    public static boolean isValid(short nameType)
    {
        return TlsUtils.isValidUint8(nameType);
    }
}
