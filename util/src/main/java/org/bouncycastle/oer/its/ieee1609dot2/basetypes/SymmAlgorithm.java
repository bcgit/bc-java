package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Enumerated;

/**
 * SymmAlgorithm ::= ENUMERATED {
 * aes128Ccm,
 * ...
 * }
 */
public class SymmAlgorithm
    extends ASN1Enumerated
{
    public static final SymmAlgorithm aes128Ccm = new SymmAlgorithm(BigInteger.ZERO);

    public SymmAlgorithm(BigInteger ordinal)
    {
        super(ordinal);
        assertValues();
    }

    protected void assertValues()
    {
        if (!hasValue(0))
        {
            throw new IllegalArgumentException("invalid enumeration value " + getValue());
        }
    }

    public static SymmAlgorithm getInstance(Object src)
    {
        if (src instanceof SymmAlgorithm)
        {
            return (SymmAlgorithm)src;
        }

        if (src != null)
        {
            return getInstance(ASN1Enumerated.getInstance(src));
        }

        return null;
    }

    private static SymmAlgorithm getInstance(ASN1Enumerated value)
    {
        if (value.hasValue(0))
        {
            return aes128Ccm;
        }
        throw new IllegalArgumentException("invalid enumeration value " + value.getValue());
    }
}
