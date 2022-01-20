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
    public static final CertificateType Explicit = new CertificateType(0);
    public static final CertificateType Implicit = new CertificateType(1);
    public static final CertificateType Extension = new CertificateType(2);

    protected CertificateType(int ordinal)
    {
        super(ordinal);
    }

    public static CertificateType getInstance(Object src)
    {
        if (src instanceof CertificateType)
        {
            return (CertificateType)src;
        }
        else
        {
            BigInteger bi = ASN1Enumerated.getInstance(src).getValue();
            switch (bi.intValue())
            {
            case 0:
                return Explicit;
            case 1:
                return Implicit;
            case 2:
                return Extension;
            default:
                throw new IllegalArgumentException("unaccounted enum value " + bi);
            }
        }
    }

}
