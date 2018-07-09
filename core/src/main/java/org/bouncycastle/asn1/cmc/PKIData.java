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
        this.controlSequence = controlSequence;
        this.reqSequence = reqSequence;
        this.cmsSequence = cmsSequence;
        this.otherMsgSequence = otherMsgSequence;
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
        TaggedAttribute[] tmp = new TaggedAttribute[controlSequence.length];

        System.arraycopy(controlSequence, 0, tmp, 0, tmp.length);

        return tmp;
    }

    public TaggedRequest[] getReqSequence()
    {
        TaggedRequest[] tmp = new TaggedRequest[reqSequence.length];

        System.arraycopy(reqSequence, 0, tmp, 0, tmp.length);

        return tmp;
    }

    public TaggedContentInfo[] getCmsSequence()
    {
        TaggedContentInfo[] tmp = new TaggedContentInfo[cmsSequence.length];

        System.arraycopy(cmsSequence, 0, tmp, 0, tmp.length);

        return tmp;
    }

    public OtherMsg[] getOtherMsgSequence()
    {
        OtherMsg[] tmp = new OtherMsg[otherMsgSequence.length];

        System.arraycopy(otherMsgSequence, 0, tmp, 0, tmp.length);

        return tmp;
    }
}
