package org.bouncycastle.oer.its.ieee1609dot2;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.util.BigIntegers;

/**
 * CertificateType ::= ENUMERATED {
 * explicit,
 * implicit,
 * ...
 * }
 */
public class CertificateType
    extends ASN1Enumerated
{
    public static final CertificateType explicit = new CertificateType(BigInteger.ZERO);
    public static final CertificateType implicit = new CertificateType(BigInteger.ONE);

    public CertificateType(BigInteger ordinal)
    {
        super(ordinal);
        assertValues();
    }

    private CertificateType(ASN1Enumerated instance)
    {
        this(instance.getValue());
    }

    public static CertificateType getInstance(Object src)
    {
        if (src instanceof CertificateType)
        {
            return (CertificateType)src;
        }

        if (src != null)
        {
            return new CertificateType(ASN1Enumerated.getInstance(src));
        }
        return null;

    }

    protected void assertValues()
    {
        if (getValue().compareTo(BigInteger.ZERO) < 0 || getValue().compareTo(BigIntegers.ONE) > 0)
        {
            throw new IllegalArgumentException("invalid enumeration value " + getValue());
        }
    }


}
