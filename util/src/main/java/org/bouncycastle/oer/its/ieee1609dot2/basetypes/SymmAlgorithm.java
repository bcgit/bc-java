package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.util.BigIntegers;

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

    private SymmAlgorithm(ASN1Enumerated enumerated)
    {
        super(enumerated.getValue());
        assertValues();
    }

    protected void assertValues()
    {
        switch (BigIntegers.intValueExact(getValue()))
        {
        case 0:
            return;
        }
        throw new IllegalArgumentException("invalid enumeration value " + getValue());
    }


    public static SymmAlgorithm getInstance(Object src)
    {
        if (src instanceof SymmAlgorithm)
        {
            return (SymmAlgorithm)src;
        }

        if (src != null)
        {
            return new SymmAlgorithm(ASN1Enumerated.getInstance(src));
        }

        return null;

    }

}
