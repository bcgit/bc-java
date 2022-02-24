package org.bouncycastle.oer.its.etsi103097.extension;

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
        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
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

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private HashedId8 issuerId;
        private ASN1Integer lastKnownCtlSequence;

        public Builder setIssuerId(HashedId8 issuerId)
        {
            this.issuerId = issuerId;
            return this;
        }

        public Builder setLastKnownCtlSequence(ASN1Integer lastKnownCtlSequence)
        {
            this.lastKnownCtlSequence = lastKnownCtlSequence;
            return this;
        }

        public EtsiTs102941CtlRequest createEtsiTs102941CtlRequest()
        {
            return new EtsiTs102941CtlRequest(issuerId, lastKnownCtlSequence);
        }

        public EtsiTs102941DeltaCtlRequest createEtsiTs102941DeltaCtlRequest()
        {
            return new EtsiTs102941DeltaCtlRequest(issuerId, lastKnownCtlSequence);
        }
    }
}
