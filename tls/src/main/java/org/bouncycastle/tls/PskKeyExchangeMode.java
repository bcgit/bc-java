package org.bouncycastle.tls;

public class PskKeyExchangeMode
{
    /*
     * RFC 8446
     */

    public static final short psk_ke = 0;
    public static final short psk_dhe_ke = 1;

    public static String getName(short pskKeyExchangeMode)
    {
        switch (pskKeyExchangeMode)
        {
        case psk_ke:
            return "psk_ke";
        case psk_dhe_ke:
            return "psk_dhe_ke";
        default:
            return "UNKNOWN";
        }
    }

    public static String getText(short pskKeyExchangeMode)
    {
        return getName(pskKeyExchangeMode) + "(" + pskKeyExchangeMode + ")";
    }
}
