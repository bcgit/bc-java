package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097Certificate;

/**
 * EaEntry ::= SEQUENCE {
 * eaCertificate     EtsiTs103097Certificate,
 * aaAccessPoint     Url,
 * itsAccessPoint    Url OPTIONAL
 * }
 */
public class EaEntry
    extends ASN1Object
{
    private final EtsiTs103097Certificate eaCertificate;
    private final Url aaAccessPoint;
    private final Url itsAccessPoint;

    public EaEntry(EtsiTs103097Certificate eaCertificate, Url aaAccessPoint, Url itsAccessPoint)
    {
        this.eaCertificate = eaCertificate;
        this.aaAccessPoint = aaAccessPoint;
        this.itsAccessPoint = itsAccessPoint;
    }

    private EaEntry(ASN1Sequence sequence)
    {
        if (sequence.size() != 3)
        {
            throw new IllegalArgumentException("expected sequence size of 3");
        }

        eaCertificate = EtsiTs103097Certificate.getInstance(sequence.getObjectAt(0));
        aaAccessPoint = Url.getInstance(sequence.getObjectAt(1));
        itsAccessPoint = OEROptional.getValue(Url.class, sequence.getObjectAt(2));
    }

    public static EaEntry getInstance(Object o)
    {
        if (o instanceof EaEntry)
        {
            return (EaEntry)o;
        }
        if (o != null)
        {
            return new EaEntry(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public EtsiTs103097Certificate getEaCertificate()
    {
        return eaCertificate;
    }

    public Url getAaAccessPoint()
    {
        return aaAccessPoint;
    }

    public Url getItsAccessPoint()
    {
        return itsAccessPoint;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{
            eaCertificate, aaAccessPoint, OEROptional.getInstance(itsAccessPoint)
        });
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private EtsiTs103097Certificate eaCertificate;
        private Url aaAccessPoint;
        private Url itsAccessPoint;

        public Builder setEaCertificate(EtsiTs103097Certificate eaCertificate)
        {
            this.eaCertificate = eaCertificate;
            return this;
        }

        public Builder setAaAccessPoint(Url aaAccessPoint)
        {
            this.aaAccessPoint = aaAccessPoint;
            return this;
        }

        public Builder setItsAccessPoint(Url itsAccessPoint)
        {
            this.itsAccessPoint = itsAccessPoint;
            return this;
        }

        public EaEntry createEaEntry()
        {
            return new EaEntry(eaCertificate, aaAccessPoint, itsAccessPoint);
        }
    }
}
