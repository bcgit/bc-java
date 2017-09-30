package com.github.gv2011.asn1;

import java.util.Date;

import com.github.gv2011.util.bytes.Bytes;

/**
 * DER Generalized time object.
 */
public class DERGeneralizedTime
    extends ASN1GeneralizedTime
{

    DERGeneralizedTime(final Bytes bytes)
    {
        super(bytes);
    }

    public DERGeneralizedTime(final Date time)
    {
        super(time);
    }

    public DERGeneralizedTime(final String time)
    {
        super(time);
    }

    // TODO: create proper DER encoding.
}
