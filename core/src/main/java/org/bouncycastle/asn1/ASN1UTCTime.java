package org.bouncycastle.asn1;

import java.util.Date;

/**
 * Public facade of {@link DERUTCTime}.
 * <p>
 * This datatype is valid only from 1950-01-01 00:00:00 UTC until 2049-12-31 23:59:59 UTC.
 */
public class ASN1UTCTime
    extends DERUTCTime
{
    ASN1UTCTime(byte[] bytes)
    {
        super(bytes);
    }

    public ASN1UTCTime(Date time)
    {
        super(time);
    }

    /**
     * The correct format for this is "YYMMDDHHMMSS'Z'".
     * The year is given in two numbers without indicating the century.
     */
    public ASN1UTCTime(String time)
    {
        super(time);
    }
}
