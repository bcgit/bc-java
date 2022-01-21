package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;

public class Uint32
    extends UintBase
{
    private static final BigInteger MAX = new BigInteger("FFFFFFFF", 16);

    public Uint32(BigInteger value)
    {
        super(value);
    }

    public Uint32(int value)
    {
        super(value);
    }

    public Uint32(long value)
    {
        super(value);
    }

    protected Uint32(ASN1Integer integer)
    {
        super(integer);

    }

    public static Uint32 getInstance(Object o)
    {
        if (o instanceof Uint8)
        {
            return (Uint32)o;
        }

        if (o != null)
        {
            return new Uint32(ASN1Integer.getInstance(o));
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
