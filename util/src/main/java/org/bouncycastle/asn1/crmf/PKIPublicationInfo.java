package org.bouncycastle.asn1.crmf;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 * PKIPublicationInfo ::= SEQUENCE {
 *                  action     INTEGER {
 *                                 dontPublish (0),
 *                                 pleasePublish (1) },
 *                  pubInfos  SEQUENCE SIZE (1..MAX) OF SinglePubInfo OPTIONAL }
 * -- pubInfos MUST NOT be present if action is "dontPublish"
 * -- (if action is "pleasePublish" and pubInfos is omitted,
 * -- "dontCare" is assumed)
 * </pre>
 */
public class PKIPublicationInfo
    extends ASN1Object
{
    public static final ASN1Integer dontPublish = ASN1Integer.ZERO;
    public static final ASN1Integer pleasePublish = ASN1Integer.ONE;

    private ASN1Integer action;
    private ASN1Sequence pubInfos;

    private PKIPublicationInfo(ASN1Sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        action = ASN1Integer.getInstance(seq.getObjectAt(0));
        if (seq.size() > 1)
        {
            pubInfos = checkPubInfos(action, ASN1Sequence.getInstance(seq.getObjectAt(1)));
        }
    }

    /**
     * RFC 4211 sec. 6.3: pubInfos MUST NOT be present if action is dontPublish, and the field is
     * SEQUENCE SIZE (1..MAX), so a present one carries at least one SinglePubInfo. "Don't care" is
     * an absent pubInfos with the pleasePublish action, not an empty or contradictory one.
     */
    private static ASN1Sequence checkPubInfos(ASN1Integer action, ASN1Sequence pubInfos)
    {
        if (dontPublish.equals(action))
        {
            throw new IllegalArgumentException("pubInfos must be absent if action is dontPublish");
        }

        if (pubInfos.size() == 0)
        {
            throw new IllegalArgumentException("pubInfos must contain at least one SinglePubInfo");
        }

        return pubInfos;
    }

    public static PKIPublicationInfo getInstance(Object o)
    {
        if (o instanceof PKIPublicationInfo)
        {
            return (PKIPublicationInfo)o;
        }

        if (o != null)
        {
            return new PKIPublicationInfo(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public PKIPublicationInfo(BigInteger action)
    {
        this(new ASN1Integer(action));
    }

    public PKIPublicationInfo(ASN1Integer action)
    {
        this.action = action;
    }

    /**
     * Constructor with a single pubInfo, assumes pleasePublish as the action.
     *
     * @param pubInfo the pubInfo to be published (can be null if don't care is required).
     */
    public PKIPublicationInfo(SinglePubInfo pubInfo)
    {
        this(pubInfo != null ? new SinglePubInfo[] { pubInfo } : (SinglePubInfo[])null);
    }

    /**
     * Constructor with multiple pubInfo, assumes pleasePublish as the action.
     *
     * @param pubInfos the pubInfos to be published (can be null if don't care is required).
     */
    public PKIPublicationInfo(SinglePubInfo[] pubInfos)
    {
        this.action = pleasePublish;

        if (pubInfos != null)
        {
            this.pubInfos = checkPubInfos(this.action, new DERSequence(pubInfos));
        }
        else
        {
            this.pubInfos = null;
        }
    }

    public ASN1Integer getAction()
    {
        return action;
    }

    public SinglePubInfo[] getPubInfos()
    {
        if (pubInfos == null)
        {
            return null;
        }

        SinglePubInfo[] results = new SinglePubInfo[pubInfos.size()];

        for (int i = 0; i != results.length; i++)
        {
            results[i] = SinglePubInfo.getInstance(pubInfos.getObjectAt(i));
        }

        return results;
    }

    /**
     * Return the primitive representation of PKIPublicationInfo.
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(action);

        if (pubInfos != null)
        {
            v.add(pubInfos);
        }

        return new DERSequence(v);
    }
}
