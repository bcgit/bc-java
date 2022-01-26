package org.bouncycastle.oer.its.etsi10309.extension;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;

/**
 * EtsiTs102941CtlRequest::= SEQUENCE {
 * issuerId             HashedId8,
 * lastKnownCtlSequence INTEGER (0..255) OPTIONAL
 * }
 */
public class EtsiTs102941CtlRequest
    extends ASN1Object
{
    private final HashedId8 issuerId;
    private final ASN1Integer lastKnownCtlSequence;


    protected EtsiTs102941CtlRequest(ASN1Sequence sequence)
    {
        if (sequence.size() != 1 && sequence.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 1 or 2");
        }

        issuerId = HashedId8.getInstance(sequence.getObjectAt(0));
        if (sequence.size() == 2)
        {
            lastKnownCtlSequence = OEROptional.getValue(ASN1Integer.class, sequence.getObjectAt(1));
        }
        else
        {
            lastKnownCtlSequence = null;
        }

    }


    public EtsiTs102941CtlRequest(HashedId8 issuerId, ASN1Integer lastKnownCtlSequence)
    {
        this.issuerId = issuerId;
        this.lastKnownCtlSequence = lastKnownCtlSequence;
    }

    public static EtsiTs102941CtlRequest getInstance(Object o)
    {
        if (o instanceof EtsiTs102941CtlRequest)
        {
            return (EtsiTs102941CtlRequest)o;
        }

        if (o != null)
        {
            return new EtsiTs102941CtlRequest(ASN1Sequence.getInstance(o));
        }

        return null;

    }

    public HashedId8 getIssuerId()
    {
        return issuerId;
    }

    public ASN1Integer getLastKnownCtlSequence()
    {
        return lastKnownCtlSequence;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{issuerId, OEROptional.getInstance(lastKnownCtlSequence)});
    }
}
