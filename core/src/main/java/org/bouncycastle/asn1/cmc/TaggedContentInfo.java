package org.bouncycastle.asn1.cmc;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.ContentInfo;

/**
 * <pre>
 * TaggedContentInfo ::= SEQUENCE {
 *       bodyPartID              BodyPartID,
 *       contentInfo             ContentInfo
 * }
 * </pre>
 */
public class TaggedContentInfo
    extends ASN1Object
{
    private final BodyPartID bodyPartID;
    private final ContentInfo contentInfo;

    public TaggedContentInfo(BodyPartID bodyPartID, ContentInfo contentInfo)
    {
        this.bodyPartID = bodyPartID;
        this.contentInfo = contentInfo;
    }

    private TaggedContentInfo(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.bodyPartID = BodyPartID.getInstance(seq.getObjectAt(0));
        this.contentInfo = ContentInfo.getInstance(seq.getObjectAt(1));
    }

    public static TaggedContentInfo getInstance(Object o)
    {
        if (o instanceof TaggedContentInfo)
        {
            return (TaggedContentInfo)o;
        }

        if (o != null)
        {
            return new TaggedContentInfo(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public static TaggedContentInfo getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(bodyPartID);
        v.add(contentInfo);

        return new DERSequence(v);
    }

    public BodyPartID getBodyPartID()
    {
        return bodyPartID;
    }

    public ContentInfo getContentInfo()
    {
        return contentInfo;
    }
}
