package org.bouncycastle.tls;

public class CertificateStatusType
{
    /*
     *  RFC 6066
     */
    public static final short ocsp = 1;

    /*
     *  RFC 6961
     */
    public static final short ocsp_multi = 2;

    public static String getName(short certificateStatusType)
    {
        switch (certificateStatusType)
        {
        case ocsp:
            return "ocsp";
        case ocsp_multi:
            return "ocsp_multi";
        default:
            return "UNKNOWN";
        }
    }

    public static String getText(short certificateStatusType)
    {
        return getName(certificateStatusType) + "(" + certificateStatusType + ")";
    }
}
