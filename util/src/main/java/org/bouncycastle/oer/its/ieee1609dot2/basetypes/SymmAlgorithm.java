package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Enumerated;

public class SymmAlgorithm
    extends ASN1Enumerated
{
    public static SymmAlgorithm aes128Ccm = new SymmAlgorithm(0);

    public SymmAlgorithm(int ordinal)
    {
        super(ordinal);

        if (ordinal != 0)
        {
            throw new IllegalArgumentException("ordinal can only be zero");
        }
    }

    public static SymmAlgorithm getInstance(Object src)
    {
        if (src == null)
        {
            return null;
        }
        else if (src instanceof SymmAlgorithm)
        {
            return (SymmAlgorithm)src;
        }
        else
        {
            BigInteger bi = ASN1Enumerated.getInstance(src).getValue();
            switch (bi.intValue())
            {
            case 0:
                return aes128Ccm;
            default:
                throw new IllegalArgumentException("unaccounted enum value " + bi);
            }
        }

    }


}
