package org.bouncycastle.oer.its.ieee1609dot2;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;

/**
 * HeaderInfoContributorId ::= INTEGER (0..255)
 * etsiHeaderInfoContributorId         HeaderInfoContributorId ::= 2
 */
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

    public HeaderInfoContributorId(ASN1Integer integer) {
        this(integer.getValue());
    }

    public static HeaderInfoContributorId getInstance(Object src)
    {
        if (src instanceof HeaderInfoContributorId)
        {
            return (HeaderInfoContributorId)src;
        }

        if (src != null)
        {
            return new HeaderInfoContributorId(ASN1Integer.getInstance(src));
        }

        return null;
    }


}
