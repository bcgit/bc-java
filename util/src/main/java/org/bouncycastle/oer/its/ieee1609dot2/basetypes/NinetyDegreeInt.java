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
public class NinetyDegreeInt
    extends ASN1Integer
{
    private static final BigInteger loweBound = new BigInteger("-900000000");
    private static final BigInteger upperBound = new BigInteger("900000000");
    private static final BigInteger unknown = new BigInteger("900000001");


    public NinetyDegreeInt(long value)
    {
        super(value);
        assertValue();
    }

    public NinetyDegreeInt(BigInteger value)
    {
        super(value);
        assertValue();
    }

    public NinetyDegreeInt(byte[] bytes)
    {
        super(bytes);
        assertValue();
    }

    public static NinetyDegreeInt getInstance(Object o)
    {
        if (o instanceof NinetyDegreeInt)
        {
            return (NinetyDegreeInt)o;
        }
        else
        {
            return new NinetyDegreeInt(ASN1Integer.getInstance(o).getValue());
        }
    }

    public void assertValue()
    {
        BigInteger bi = getValue();

        if (bi.compareTo(loweBound) < 0)
        {
            throw new IllegalStateException("ninety degree int cannot be less than -900000000");
        }

        if (bi.equals(unknown))
        {
            return;
        }

        if (bi.compareTo(upperBound) > 0)
        {
            throw new IllegalStateException("ninety degree int cannot be greater than 900000000");
        }

    }

}
