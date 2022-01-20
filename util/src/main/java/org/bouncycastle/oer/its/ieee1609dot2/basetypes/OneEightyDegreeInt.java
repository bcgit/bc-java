package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;

/**
 * NinetyDegreeInt ::= INTEGER {
 * min (-900000000),
 * max (900000000),
 * unknown (900000001)
 * }
 */
public class OneEightyDegreeInt
    extends ASN1Integer
{
    private static final BigInteger loweBound = new BigInteger("-1799999999");
    private static final BigInteger upperBound = new BigInteger("1800000000");
    private static final BigInteger unknown = new BigInteger("1800000001");


    public OneEightyDegreeInt(long value)
    {
        super(value);
        assertValue();
    }

    public OneEightyDegreeInt(BigInteger value)
    {
        super(value);
        assertValue();
    }

    public OneEightyDegreeInt(byte[] bytes)
    {
        super(bytes);
        assertValue();
    }

    public static OneEightyDegreeInt getInstance(Object o)
    {
        if (o instanceof OneEightyDegreeInt)
        {
            return (OneEightyDegreeInt)o;
        }
        else
        {
            return new OneEightyDegreeInt(ASN1Integer.getInstance(o).getValue());
        }
    }

    public void assertValue()
    {
        BigInteger bi = getValue();

        if (bi.compareTo(loweBound) < 0)
        {
            throw new IllegalStateException("one eighty degree int cannot be less than -1799999999");
        }

        if (bi.equals(unknown))
        {
            return;
        }

        if (bi.compareTo(upperBound) > 0)
        {
            throw new IllegalStateException("one eighty degree int cannot be greater than 1800000000");
        }

    }

}
