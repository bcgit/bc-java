package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;

public class Psid
    extends ASN1Integer
{

    public Psid(long value)
    {
        super(value);
        validate();
    }


    public Psid(BigInteger value)
    {
        super(value);
        validate();
    }

    public Psid(byte[] bytes)
    {
        super(bytes);
        validate();
    }

    public static Psid getInstance(Object o)
    {
        if (o instanceof Psid)
        {
            return (Psid)o;
        }
        return new Psid(ASN1Integer.getInstance(o).getValue());
    }

    private void validate()
    {
        if (BigInteger.ZERO.compareTo(getValue()) >= 0)
        {
            throw new IllegalStateException("psid must be greater than zero");
        }
    }
}
