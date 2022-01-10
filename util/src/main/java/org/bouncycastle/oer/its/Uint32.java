package org.bouncycastle.oer.its;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

public class Uint32
    extends ASN1Object
{
    private final long value;

    public Uint32(long value)
    {
        this.value = verify(value);
    }

    public Uint32(BigInteger value)
    {
        this.value = verify(value.longValue());
    }

    public static Uint32 getInstance(Object o)
    {
        if (o instanceof Uint32)
        {
            return (Uint32)o;
        }
        else
        {
            return new Uint32(ASN1Integer.getInstance(o).getValue());
        }
    }

    protected long verify(long value)
    {
        if (value < 0)
        {
            throw new IllegalArgumentException("Uint32 must be >= 0");
        }
        if (value > 0xFFFFFFFFL)
        {
            throw new IllegalArgumentException("Uint32 must be <= 0xFFFFFFFF");
        }

        return value;
    }

    public long getValue()
    {
        return value;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new ASN1Integer(value);
    }
}
