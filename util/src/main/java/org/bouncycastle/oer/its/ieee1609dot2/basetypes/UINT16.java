package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;

public class UINT16
    extends UintBase
{
    private static final BigInteger MAX = BigInteger.valueOf(65535);

    public UINT16(BigInteger value)
    {
        super(value);
    }

    public UINT16(int value)
    {
        super(value);
    }

    public UINT16(long value)
    {
        super(value);
    }

    protected UINT16(ASN1Integer integer)
    {
        super(integer);

    }

    public static UINT16 getInstance(Object o)
    {
        if (o instanceof UINT16)
        {
            return (UINT16)o;
        }

        if (o != null)
        {
            return new UINT16(ASN1Integer.getInstance(o));
        }

        return null;
    }

    public static UINT16 valueOf(int i)
    {
        return new UINT16(i);
    }

    @Override
    protected void assertLimit()
    {
        if (value.signum() < 0)
        {
            throw new IllegalArgumentException("value must not be negative");
        }
        if (value.compareTo(MAX) > 0)
        {
            throw new IllegalArgumentException("value must not exceed " + MAX.toString(16));
        }
    }
}
