package org.bouncycastle.oer.its.etsi103097.extension;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;

/**
 * EtsiTs102941DeltaCtlRequest::= EtsiTs102941CtlRequest
 * and
 * EtsiTs102941CtlRequest::= SEQUENCE {
 * issuerId             HashedId8,
 * lastKnownCtlSequence INTEGER (0..255) OPTIONAL
 * }
 */
public class EtsiTs102941DeltaCtlRequest
    extends EtsiTs102941CtlRequest
{

    private EtsiTs102941DeltaCtlRequest(ASN1Sequence sequence)
    {
        super(sequence);
    }

    public EtsiTs102941DeltaCtlRequest(HashedId8 issuerId, ASN1Integer lastKnownCtlSequence)
    {
        super(issuerId, lastKnownCtlSequence);
    }

    public static EtsiTs102941DeltaCtlRequest getInstance(Object o)
    {
        if (o instanceof EtsiTs102941DeltaCtlRequest)
        {
            return (EtsiTs102941DeltaCtlRequest)o;
        }

        if (o != null)
        {
            return new EtsiTs102941DeltaCtlRequest(ASN1Sequence.getInstance(o));
        }

        return null;

    }

    public static EtsiTs102941DeltaCtlRequest.Builder builder()
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

        public EtsiTs102941DeltaCtlRequest build()
        {
            return new EtsiTs102941DeltaCtlRequest(issuerId, lastKnownCtlSequence);
        }
    }


}
