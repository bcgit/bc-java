package org.bouncycastle.its.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 *     LinkageData ::= SEQUENCE {
 *         iCert IValue,
 *         linkage-value LinkageValue,
 *         group-linkage-value GroupLinkageValue OPTIONAL
 *     }
 * </pre>
 */
public class LinkageData
    extends ASN1Object
{
    private final IValue iCert;
    private final LinkageValue linkageValue;
    private final GroupLinkageValue groupLinkageValue;

    private LinkageData(ASN1Sequence seq)
    {
        if (seq.size() != 2 && seq.size() != 3)
        {
            throw new IllegalArgumentException("sequence must be size 2 or 3");
        }
        
        this.iCert = IValue.getInstance(seq.getObjectAt(2));
        this.linkageValue = LinkageValue.getInstance(seq.getObjectAt(2));
        this.groupLinkageValue = GroupLinkageValue.getInstance(seq.getObjectAt(2));
    }

    public static LinkageData getInstance(Object src)
    {
        if (src instanceof LinkageData)
        {
            return (LinkageData)src;
        }
        else if (src != null)
        {
            // TODO: need choice processing here
            return new LinkageData(ASN1Sequence.getInstance(src));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        return new DERSequence(v);
    }
}
