package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ItsUtils;

/**
 * <pre>
 *     GroupLinkageValue ::= SEQUENCE {
 *         jValue OCTET STRING (SIZE(4))
 *         value OCTET STRING (SIZE(9))
 *     }
 * </pre>
 */
public class GroupLinkageValue
    extends ASN1Object
{
    private final ASN1OctetString jValue;
    private final ASN1OctetString value;

    private GroupLinkageValue(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("sequence not length 2");
        }

        jValue = ASN1OctetString.getInstance(seq.getObjectAt(0));
        value = ASN1OctetString.getInstance(seq.getObjectAt(1));
    }

    public static GroupLinkageValue getInstance(Object src)
    {
        if (src instanceof GroupLinkageValue)
        {
            return (GroupLinkageValue)src;
        }
        else if (src != null)
        {
            return new GroupLinkageValue(ASN1Sequence.getInstance(src));
        }

        return null;
    }

    public ASN1OctetString getjValue()
    {
        return jValue;
    }

    public ASN1OctetString getValue()
    {
        return value;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(jValue, value);
    }
}
