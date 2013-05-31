package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DLSet;

public class Attributes
    extends ASN1Object
{
    private ASN1Set attributes;

    private Attributes(ASN1Set set)
    {
        attributes = set;
    }

    public Attributes(ASN1EncodableVector v)
    {
        attributes = new DLSet(v);
    }

    public static Attributes getInstance(Object obj)
    {
        if (obj instanceof Attributes)
        {
            return (Attributes)obj;
        }
        else if (obj != null)
        {
            return new Attributes(ASN1Set.getInstance(obj));
        }

        return null;
    }

    public Attribute[] getAttributes()
    {
        Attribute[] rv = new Attribute[attributes.size()];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = Attribute.getInstance(attributes.getObjectAt(i));
        }

        return rv;
    }

    /**
     * <pre>
     * Attributes ::=
     *   SET SIZE(1..MAX) OF Attribute -- according to RFC 5652
     * </pre>
     * @return
     */
    public ASN1Primitive toASN1Primitive()
    {
        return attributes;
    }
}
