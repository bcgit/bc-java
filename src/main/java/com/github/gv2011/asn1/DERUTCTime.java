package com.github.gv2011.asn1;

import java.util.Date;

import com.github.gv2011.util.bytes.Bytes;

/**
 * DER UTC time object.
 */
@Deprecated //see TODO
public final class DERUTCTime extends ASN1UTCTime
{
    DERUTCTime(final Bytes bytes)
    {
        super(bytes);
    }

    public DERUTCTime(final Date time)
    {
        super(time);
    }

    public DERUTCTime(final String time)
    {
        super(time);
    }

    // TODO: create proper DER encoding.
}
