package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;

public class Uint16
    extends UintBase
{
    private static final BigInteger MAX = BigInteger.valueOf(65535);

    public Uint16(BigInteger value)
    {
        super(value);
    }

    public Uint16(int value)
    {
        super(value);
    }

    public Uint16(long value)
    {
        super(value);
    }

    protected Uint16(ASN1Integer integer)
    {
        super(integer);

    }

    public static Uint16 getInstance(Object o)
    {
        if (o instanceof Uint16)
        {
            return (Uint16)o;
        }

        if (o != null)
        {
            return new Uint16(ASN1Integer.getInstance(o));
        }

        return null;
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
