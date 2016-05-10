package com.github.gv2011.bcasn;

import java.util.Date;

/**
 * DER UTC time object.
 */
public class DERUTCTime
    extends ASN1UTCTime
{
    DERUTCTime(byte[] bytes)
    {
        super(bytes);
    }

    public DERUTCTime(Date time)
    {
        super(time);
    }

    public DERUTCTime(String time)
    {
        super(time);
    }

    // TODO: create proper DER encoding.
}
