package org.bouncycastle.oer.its.ieee1609dot2;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;

public class HeaderInfoContributorId
    extends ASN1Integer
{

    public HeaderInfoContributorId(long value)
    {
        super(value);
    }

    public HeaderInfoContributorId(BigInteger value)
    {
        super(value);
    }

    public HeaderInfoContributorId(byte[] bytes)
    {
        super(bytes);
    }

    public static HeaderInfoContributorId getInstance(Object src)
    {
        if (src instanceof HeaderInfoContributorId)
        {
            return (HeaderInfoContributorId)src;
        }

        ASN1Integer integer = ASN1Integer.getInstance(src);
        return new HeaderInfoContributorId(integer.getValue());
    }


}
