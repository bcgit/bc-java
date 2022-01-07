package org.bouncycastle.oer.its;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

public class Uint8
    extends ASN1Object
{
    private final int value;

    public Uint8(int value)
    {
        this.value = verify(value);
    }

    public Uint8(BigInteger value)
    {
        this.value = value.intValue();
    }

    public static Uint8 getInstance(Object o)
    {
        if (o instanceof Uint8)
        {
            return (Uint8)o;
        }
        else
        {
            return new Uint8(ASN1Integer.getInstance(o).getValue());
        }
    }

    protected int verify(int value)
    {
        if (value < 0)
        {
            throw new IllegalArgumentException("Uint16 must be >= 0");
        }
        if (value > 0xFF)
        {
            throw new IllegalArgumentException("Uint16 must be <= 0xFF");
        }

        return value;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new ASN1Integer(value);
    }

    public int getValue()
    {
        return value;
    }
}
