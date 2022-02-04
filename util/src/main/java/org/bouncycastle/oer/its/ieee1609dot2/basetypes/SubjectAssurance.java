package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;

/**
 * SubjectAssurance ::= OCTET STRING (SIZE(1))
 */
public class SubjectAssurance
    extends DEROctetString
{

    public SubjectAssurance(byte[] string)
    {
        super(string);
        if (string.length != 1)
        {
            throw new IllegalArgumentException("length is not 1");
        }
    }

    private SubjectAssurance(ASN1OctetString string)
    {
        this(string.getOctets());
    }

    public static SubjectAssurance getInstance(Object o)
    {
        if (o instanceof SubjectAssurance)
        {
            return (SubjectAssurance)o;
        }

        if (o != null)
        {
            return new SubjectAssurance(DEROctetString.getInstance(o));
        }

        return null;

    }
}
