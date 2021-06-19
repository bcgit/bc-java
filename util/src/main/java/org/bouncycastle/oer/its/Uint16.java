package org.bouncycastle.oer.its;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;

public class Uint16
    extends ASN1Integer
{

    public static Uint16 getInstance(Object o)
    {
        if (o instanceof Uint16)
        {
            return (Uint16)o;
        }
        else
        {
            return new Uint16(ASN1Integer.getInstance(o).getValue());
        }
    }

    public Uint16(long value)
    {
        super(value);
        verify();
    }

    public Uint16(BigInteger value)
    {
        super(value);
        verify();
    }

    public Uint16(byte[] bytes)
    {
        super(bytes);
        verify();
    }

    private void verify()
    {
        if (getValue().compareTo(BigInteger.ZERO) < 0)
        {
            throw new IllegalStateException("uint16 must be >=0");
        }
        if (getValue().compareTo(BigInteger.valueOf(255)) > 0)
        {
            throw new IllegalStateException("uint16 must be <=255");
        }
    }
}
