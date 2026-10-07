package org.bouncycastle.oer.its.ieee1609dot2;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Enumerated;

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

    public static CertificateType getInstance(Object src)
    {
        if (src instanceof CertificateType)
        {
            return (CertificateType)src;
        }

        if (src != null)
        {
            return getInstance(ASN1Enumerated.getInstance(src));
        }
        return null;
    }

    private static CertificateType getInstance(ASN1Enumerated value)
    {
        if (value.hasValue(0))
        {
            return explicit;
        }
        if (value.hasValue(1))
        {
            return implicit;
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
