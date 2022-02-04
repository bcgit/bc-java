package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;

public class CountryOnly
    extends UINT16
    implements RegionInterface
{
    public CountryOnly(int value)
    {
        super(value);
    }

    public CountryOnly(BigInteger value)
    {
        super(value);
    }

    public static CountryOnly getInstance(Object o)
    {
        if (o instanceof CountryOnly)
        {
            return (CountryOnly)o;
        }

        if (o != null)
        {
            return new CountryOnly(ASN1Integer.getInstance(o).getValue());
        }

        return null;
    }
}
