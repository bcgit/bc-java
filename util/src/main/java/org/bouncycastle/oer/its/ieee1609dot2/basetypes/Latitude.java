package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;

/**
 * <pre>
 *     Latitude ::= NinetyDegreeInt
 * </pre>
 */
public class Latitude
    extends NinetyDegreeInt
{

    public Latitude(long value)
    {
        super(value);
    }

    public Latitude(BigInteger value)
    {
        super(value);
    }


    private Latitude(ASN1Integer instance)
    {
        this(instance.getValue());
    }

    public static Latitude getInstance(Object o)
    {
        if (o instanceof Latitude)
        {
            return (Latitude)o;
        }

        if (o != null)
        {
            return new Latitude(ASN1Integer.getInstance(o));
        }

        return null;
    }


}
