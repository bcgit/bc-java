package org.bouncycastle.its.asn1;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * CertificateType ::= ENUMERATED {
 * explicit,
 * implicit,
 * ...
 * }
 */
public class CertificateType
{

    public static final CertificateType Explicit = new CertificateType(0);
    public static final CertificateType Implicit = new CertificateType(1);
    private final ASN1Enumerated enumerated;

    protected CertificateType(int ordinal)
    {
        enumerated = new ASN1Enumerated(ordinal);
    }

    private CertificateType(ASN1Enumerated enumerated)
    {
        this.enumerated = enumerated;
    }

    public CertificateType getInstance(Object src)
    {
        if (src == null)
        {
            return null;
        }
        else if (src instanceof CertificateType)
        {
            return (CertificateType)src;
        }
        else
        {
            return new CertificateType(ASN1Enumerated.getInstance(src));
        }
    }

    public ASN1Primitive toASN1Primitive()
    {
        return enumerated;
    }
}
