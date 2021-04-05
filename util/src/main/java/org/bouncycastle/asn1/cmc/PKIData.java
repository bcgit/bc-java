package org.bouncycastle.asn1.cmc;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 * PKIData ::= SEQUENCE {
 * controlSequence    SEQUENCE SIZE(0..MAX) OF TaggedAttribute,
 * reqSequence        SEQUENCE SIZE(0..MAX) OF TaggedRequest,
 * cmsSequence        SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
 * otherMsgSequence   SEQUENCE SIZE(0..MAX) OF OtherMsg
 * }
 * </pre>
 */
public class PKIData
    extends ASN1Object
{
    private final TaggedAttribute[] controlSequence;
    private final TaggedRequest[] reqSequence;
    private final TaggedContentInfo[] cmsSequence;
    private final OtherMsg[] otherMsgSequence;


    public PKIData(
        TaggedAttribute[] controlSequence,
        TaggedRequest[] reqSequence,
        TaggedContentInfo[] cmsSequence,
        OtherMsg[] otherMsgSequence)
    {
        this.controlSequence = copy(controlSequence);
        this.reqSequence = copy(reqSequence);
        this.cmsSequence = copy(cmsSequence);
        this.otherMsgSequence = copy(otherMsgSequence);
    }

    private PKIData(ASN1Sequence seq)
    {
        if (seq.size() != 4)
        {
            throw new IllegalArgumentException("Sequence not 4 elements.");
        }

        ASN1Sequence s = ((ASN1Sequence)seq.getObjectAt(0));
        controlSequence = new TaggedAttribute[s.size()];
        for (int t = 0; t < controlSequence.length; t++)
        {
            controlSequence[t] = TaggedAttribute.getInstance(s.getObjectAt(t));
        }

        s = ((ASN1Sequence)seq.getObjectAt(1));
        reqSequence = new TaggedRequest[s.size()];
        for (int t = 0; t < reqSequence.length; t++)
        {
            reqSequence[t] = TaggedRequest.getInstance(s.getObjectAt(t));
        }

        s = ((ASN1Sequence)seq.getObjectAt(2));
        cmsSequence = new TaggedContentInfo[s.size()];
        for (int t = 0; t < cmsSequence.length; t++)
        {
            cmsSequence[t] = TaggedContentInfo.getInstance(s.getObjectAt(t));
        }

        s = ((ASN1Sequence)seq.getObjectAt(3));
        otherMsgSequence = new OtherMsg[s.size()];
        for (int t = 0; t < otherMsgSequence.length; t++)
        {
            otherMsgSequence[t] = OtherMsg.getInstance(s.getObjectAt(t));
        }
    }

    public static PKIData getInstance(Object src)
    {
        if (src instanceof PKIData)
        {
            return (PKIData)src;
        }
        if (src != null)
        {
            return new PKIData(ASN1Sequence.getInstance(src));
        }
        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{
            new DERSequence(controlSequence),
            new DERSequence(reqSequence),
            new DERSequence(cmsSequence),
            new DERSequence(otherMsgSequence)
        });

    }

    public TaggedAttribute[] getControlSequence()
    {
        return copy(controlSequence);
    }

    private TaggedAttribute[] copy(TaggedAttribute[] taggedAtts)
    {
        TaggedAttribute[] tmp = new TaggedAttribute[taggedAtts.length];

        System.arraycopy(taggedAtts, 0, tmp, 0, tmp.length);

        return tmp;
    }

    public TaggedRequest[] getReqSequence()
    {
        return copy(reqSequence);
    }

    private TaggedRequest[] copy(TaggedRequest[] taggedReqs)
    {
        TaggedRequest[] tmp = new TaggedRequest[taggedReqs.length];

        System.arraycopy(taggedReqs, 0, tmp, 0, tmp.length);

        return tmp;
    }

    public TaggedContentInfo[] getCmsSequence()
    {
        return copy(cmsSequence);
    }

    private TaggedContentInfo[] copy(TaggedContentInfo[] taggedConts)
    {
        TaggedContentInfo[] tmp = new TaggedContentInfo[taggedConts.length];

        System.arraycopy(taggedConts, 0, tmp, 0, tmp.length);

        return tmp;
    }

    public OtherMsg[] getOtherMsgSequence()
    {
        return copy(otherMsgSequence);
    }

    private OtherMsg[] copy(OtherMsg[] otherMsgs)
    {
        OtherMsg[] tmp = new OtherMsg[otherMsgs.length];

        System.arraycopy(otherMsgs, 0, tmp, 0, tmp.length);

        return tmp;
    }
}
