package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Enumerated;

/**
 * HashAlgorithm ::= ENUMERATED {
 * sha256,
 * ...,
 * sha384
 * }
 */
public class HashAlgorithm
    extends ASN1Enumerated
{

    public static final HashAlgorithm sha256 = new HashAlgorithm(BigInteger.ZERO);
    public static final HashAlgorithm sha384 = new HashAlgorithm(BigInteger.ONE);


    public HashAlgorithm(BigInteger integer)
    {
        super(integer);
        assertValues();
    }


    public static HashAlgorithm getInstance(Object src)
    {
        if (src instanceof HashAlgorithm)
        {
            return (HashAlgorithm)src;
        }

        if (src != null)
        {
            return getInstance(ASN1Enumerated.getInstance(src));
        }

        return null;
    }

    private static HashAlgorithm getInstance(ASN1Enumerated value)
    {
        if (value.hasValue(0))
        {
            return sha256;
        }
        if (value.hasValue(1))
        {
            return sha384;
        }
        throw new IllegalArgumentException("invalid enumeration value " + value.getValue());
    }

    protected void assertValues()
    {
        if (!hasValue(0) && !hasValue(1))
        {
            throw new IllegalArgumentException("invalid enumeration value " + getValue());
        }
    }
}
