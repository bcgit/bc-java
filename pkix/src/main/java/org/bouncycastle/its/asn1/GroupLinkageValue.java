package org.bouncycastle.its.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

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
    private byte[] jValue;
    private byte[] value;

    private GroupLinkageValue(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("sequence not length 2");
        }

        jValue = Utils.octetStringFixed(ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets(), 4);
        value = Utils.octetStringFixed(ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets(), 9);
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

    public byte[] getJValue()
    {
        return jValue;
    }

    public byte[] getValue()
    {
        return value;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector avec = new ASN1EncodableVector();
        avec.add(new DEROctetString(jValue));
        avec.add(new DEROctetString(value));
        return new DERSequence(avec);
    }
}
