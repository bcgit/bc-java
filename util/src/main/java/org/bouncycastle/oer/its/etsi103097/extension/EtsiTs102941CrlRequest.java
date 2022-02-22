package org.bouncycastle.oer.its.etsi103097.extension;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Time32;

/**
 * EtsiTs102941CrlRequest::= SEQUENCE {
 * issuerId        HashedId8,
 * lastKnownUpdate Time32 OPTIONAL
 * }
 */
public class EtsiTs102941CrlRequest
    extends ASN1Object
{
    private final HashedId8 issuerId;
    private final Time32 lastKnownUpdate;

    public EtsiTs102941CrlRequest(HashedId8 issuerId, Time32 lastKnownUpdate)
    {
        this.issuerId = issuerId;
        this.lastKnownUpdate = lastKnownUpdate;
    }

    private EtsiTs102941CrlRequest(ASN1Sequence instance)
    {
        if (instance.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }

        issuerId = HashedId8.getInstance(instance.getObjectAt(0));
        if (instance.size() > 1)
        {
            lastKnownUpdate = OEROptional.getValue(Time32.class, instance.getObjectAt(1));
        }
        else
        {
            lastKnownUpdate = null;
        }
    }

    public static EtsiTs102941CrlRequest getInstance(Object o)
    {
        if (o instanceof EtsiTs102941CrlRequest)
        {
            return (EtsiTs102941CrlRequest)o;
        }
        if (o != null)
        {
            return new EtsiTs102941CrlRequest(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public HashedId8 getIssuerId()
    {
        return issuerId;
    }

    public Time32 getLastKnownUpdate()
    {
        return lastKnownUpdate;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{issuerId, OEROptional.getInstance(lastKnownUpdate)});
    }

    public static class Builder
    {
        private HashedId8 issuerId;
        private Time32 lastKnownUpdate;

        public Builder setIssuerId(HashedId8 issuerId)
        {
            this.issuerId = issuerId;
            return this;
        }

        public Builder setLastKnownUpdate(Time32 lastKnownUpdate)
        {
            this.lastKnownUpdate = lastKnownUpdate;
            return this;
        }

        public EtsiTs102941CrlRequest createEtsiTs102941CrlRequest()
        {
            return new EtsiTs102941CrlRequest(issuerId, lastKnownUpdate);
        }
    }

}
