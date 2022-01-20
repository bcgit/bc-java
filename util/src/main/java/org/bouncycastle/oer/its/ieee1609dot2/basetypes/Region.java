package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;

public class Region
    extends Uint16
{
    public Region(int value)
    {
        super(value);
    }

    public Region(BigInteger value)
    {
        super(value);
    }

    public static Region getInstance(Object o)
    {
        if (o instanceof Region)
        {
            return (Region)o;
        }
        else
        {
            return new Region(ASN1Integer.getInstance(o).getValue());
        }
    }
}
