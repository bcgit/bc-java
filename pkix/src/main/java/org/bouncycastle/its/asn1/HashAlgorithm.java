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
public class HashAlgorithm
{

    public static final HashAlgorithm sha256 = new HashAlgorithm(0);
    public static final HashAlgorithm sha384 = new HashAlgorithm(1);
    private final ASN1Enumerated enumerated;

    protected HashAlgorithm(int ordinal)
    {
        enumerated = new ASN1Enumerated(ordinal);
    }

    private HashAlgorithm(ASN1Enumerated enumerated)
    {
        this.enumerated = enumerated;
    }

    public HashAlgorithm getInstance(Object src)
    {
        if (src == null)
        {
            return null;
        }
        else if (src instanceof HashAlgorithm)
        {
            return (HashAlgorithm)src;
        }
        else
        {
            return new HashAlgorithm(ASN1Enumerated.getInstance(src));
        }
    }

    public ASN1Primitive toASN1Primitive()
    {
        return enumerated;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }

        HashAlgorithm that = (HashAlgorithm)o;

        return enumerated != null ? enumerated.equals(that.enumerated) : that.enumerated == null;
    }

    @Override
    public int hashCode()
    {
        return enumerated != null ? enumerated.hashCode() : 0;
    }
}
