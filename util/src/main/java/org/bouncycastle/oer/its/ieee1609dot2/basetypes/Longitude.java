package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;

/**
 * <pre>
 *     Latitude ::= OneEightyDegreeInt
 *
 *     OneEightyDegreeInt ::= INTEGER {
 *     min          (-1799999999),
 *     max          (1800000000),
 *     unknown      (1800000001)
 *   } (-1799999999..1800000001)
 * </pre>
 */
public class Longitude
    extends OneEightyDegreeInt
{
    public Longitude(long value)
    {
        super(value);
    }


    public Longitude(BigInteger value)
    {
        super(value);
    }

    private Longitude(ASN1Integer i)
    {
        this(i.getValue());
    }

    public static Longitude getInstance(Object o)
    {
        if (o instanceof Longitude)
        {
            return (Longitude)o;
        }

        if (o != null)
        {
            return new Longitude(ASN1Integer.getInstance(o));
        }
        return null;

    }

}
