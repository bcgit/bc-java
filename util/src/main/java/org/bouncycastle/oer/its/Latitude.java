package org.bouncycastle.oer.its;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;

/**
 * <pre>
 *     Latitude ::= NinetyDegreeInt
 * </pre>
 */
public class Latitude
    extends NinetyDegreeInt
{

    public static Latitude getInstance(Object o)
    {
        if (o instanceof Latitude)
        {
            return (Latitude)o;
        }
        else if (o instanceof NinetyDegreeInt)
        {
            return new Latitude(((NinetyDegreeInt)o).getValue());
        }
        else
        {
            return getInstance(ASN1Integer.getInstance(o));
        }
    }


    public Latitude(long value)
    {
        super(value);
    }

    public Latitude(BigInteger value)
    {
        super(value);
    }

    public Latitude(byte[] bytes)
    {
        super(bytes);
    }

    public static Latitude getInstance(ASN1Encodable objectAt)
    {
        return null;
    }

}
