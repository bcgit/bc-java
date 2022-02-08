package org.bouncycastle.oer.its.ieee1609dot2;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * HeaderInfoContributorId ::= INTEGER (0..255)
 * etsiHeaderInfoContributorId         HeaderInfoContributorId ::= 2
 */
public class HeaderInfoContributorId
    extends ASN1Object

{
    private final BigInteger contributorId;

    private static final BigInteger MAX = BigInteger.valueOf(255);

    public HeaderInfoContributorId(long value)
    {
        this(BigInteger.valueOf(value));
    }

    public HeaderInfoContributorId(BigInteger value)
    {
        if (value.signum() < 0 && value.compareTo(MAX) > 0)
        {
            throw new IllegalArgumentException("contributor id " + value + " is out of range 0..255");
        }
        this.contributorId = value;
    }

    private HeaderInfoContributorId(ASN1Integer integer)
    {
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

    public BigInteger getContributorId()
    {
        return contributorId;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new ASN1Integer(contributorId);
    }
}
