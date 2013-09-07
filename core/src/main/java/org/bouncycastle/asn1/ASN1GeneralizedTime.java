package org.bouncycastle.asn1;

import java.util.Date;

/**
 * One second resolution date+time on UTC timezone (Z)
 * with 4 digit year (valid from 0001 to 9999).
 * <p>
 * Timestamp format is:  yyyymmddHHMMSS'Z'
 */

public class ASN1GeneralizedTime
    extends DERGeneralizedTime
{
    ASN1GeneralizedTime(byte[] bytes)
    {
        super(bytes);
    }

    /**
     * Construct a GeneralizedTime based on Java java.util.Date 
     */
    public ASN1GeneralizedTime(Date time)
    {
        super(time);
    }

    /**
     * Construct a GeneralizedTime based on a String of format:  yyyymmddHHMMSS'Z'
     */
    public ASN1GeneralizedTime(String time)
    {
        super(time);
    }
}
