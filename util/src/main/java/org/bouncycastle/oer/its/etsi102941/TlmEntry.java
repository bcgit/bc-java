package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097Certificate;

/**
 * TlmEntry::= SEQUENCE {
 * selfSignedTLMCertificate EtsiTs103097Certificate,
 * successorTo              EtsiTs103097Certificate OPTIONAL,
 * accessPoint              Url
 * }
 */
public class TlmEntry
    extends ASN1Object
{

    private final EtsiTs103097Certificate selfSignedTLMCertificate;
    private final EtsiTs103097Certificate successorTo;
    private final Url accessPoint;

    public TlmEntry(EtsiTs103097Certificate selfSignedTLMCertificate, EtsiTs103097Certificate successorTo, Url accessPoint)
    {
        this.selfSignedTLMCertificate = selfSignedTLMCertificate;
        this.successorTo = successorTo;
        this.accessPoint = accessPoint;
    }


    private TlmEntry(ASN1Sequence sequence)
    {
        if (sequence.size() != 3)
        {
            throw new IllegalArgumentException("expected sequence size of 3");
        }
        selfSignedTLMCertificate = EtsiTs103097Certificate.getInstance(sequence.getObjectAt(0));
        successorTo = OEROptional.getValue(EtsiTs103097Certificate.class, sequence.getObjectAt(1));
        accessPoint = Url.getInstance(sequence.getObjectAt(2));
    }


    public static TlmEntry getInstance(Object o)
    {
        if (o instanceof TlmEntry)
        {
            return (TlmEntry)o;
        }

        if (o != null)
        {
            return new TlmEntry(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public EtsiTs103097Certificate getSelfSignedTLMCertificate()
    {
        return selfSignedTLMCertificate;
    }

    public EtsiTs103097Certificate getSuccessorTo()
    {
        return successorTo;
    }

    public Url getAccessPoint()
    {
        return accessPoint;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{selfSignedTLMCertificate, OEROptional.getInstance(successorTo), accessPoint});
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private EtsiTs103097Certificate selfSignedTLMCertificate;
        private EtsiTs103097Certificate successorTo;
        private Url accessPoint;

        public Builder setSelfSignedTLMCertificate(EtsiTs103097Certificate selfSignedTLMCertificate)
        {
            this.selfSignedTLMCertificate = selfSignedTLMCertificate;
            return this;
        }

        public Builder setSuccessorTo(EtsiTs103097Certificate successorTo)
        {
            this.successorTo = successorTo;
            return this;
        }

        public Builder setAccessPoint(Url accessPoint)
        {
            this.accessPoint = accessPoint;
            return this;
        }

        public TlmEntry createTlmEntry()
        {
            return new TlmEntry(selfSignedTLMCertificate, successorTo, accessPoint);
        }
    }
}
