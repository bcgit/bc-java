package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;

/**
 * KnownLatitude ::= NinetyDegreeInt (min..max)
 */
public class KnownLatitude
    extends NinetyDegreeInt
{
    public KnownLatitude(long value)
    {
        super(value);
    }

    public KnownLatitude(BigInteger value)
    {
        super(value);
    }

    private KnownLatitude(ASN1Integer integer)
    {
        this(integer.getValue());
    }


    public static KnownLatitude getInstance(Object o)
    {
        if (o instanceof KnownLatitude)
        {
            return (KnownLatitude)o;
        }
        if (o != null)
        {
            return new KnownLatitude(ASN1Integer.getInstance(o));
        }
        return null;
    }

}
