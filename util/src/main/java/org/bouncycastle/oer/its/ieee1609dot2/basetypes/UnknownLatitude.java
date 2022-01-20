package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Integer;

// UnknownLatitude ::= NinetyDegreeInt (unknown)
public class UnknownLatitude
    extends Latitude
{

    public static UnknownLatitude INSTANCE = new UnknownLatitude();

    private UnknownLatitude()
    {
        super(900000001);
    }

    public static UnknownLatitude getInstance(Object o)
    {
        if (o instanceof UnknownLatitude)
        {
            return (UnknownLatitude)o;
        }
        if (o != null)
        {
            ASN1Integer integer = ASN1Integer.getInstance(o);
            if (integer.getValue().intValue() != 900000001)
            {
                throw new IllegalArgumentException("value " + integer.getValue() + " is not unknown value of 900000001");
            }
            return INSTANCE;
        }
        return null;
    }

}
