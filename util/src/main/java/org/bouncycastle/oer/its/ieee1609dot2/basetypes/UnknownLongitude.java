package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Integer;


/**
 * UnknownLongitude ::= OneEightyDegreeInt (unknown)
 * The value 1,800,000,001 indicates that the longitude was not
 * available to the sender.
 */
public class UnknownLongitude
    extends Longitude
{

    public static final UnknownLongitude INSTANCE = new UnknownLongitude();

    public UnknownLongitude()
    {
        super(1800000001);
    }

    public static UnknownLongitude getInstance(Object o)
    {
        if (o instanceof UnknownLongitude)
        {
            return (UnknownLongitude)o;
        }

        if (o != null)
        {
            ASN1Integer integer = ASN1Integer.getInstance(o);
            if (integer.getValue().intValue() != 1800000001)
            {
                throw new IllegalArgumentException("value " + integer.getValue() + " is not 1800000001");
            }
            return INSTANCE;
        }
        return null;
    }

}
