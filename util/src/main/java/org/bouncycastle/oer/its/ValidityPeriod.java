package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 *     ValidityPeriod ::= SEQUENCE {
 *         start Time32,
 *         duration Duration
 *     }
 * </pre>
 */
public class ValidityPeriod
    extends ASN1Object
{
    private final ASN1Integer time32;
    private final Duration duration;


    public ValidityPeriod(ASN1Integer time32, Duration duration)
    {
        this.time32 = time32;
        this.duration = duration;
    }

    public static ValidityPeriod getInstance(Object o)
    {
        if (o instanceof ValidityPeriod)
        {
            return (ValidityPeriod)o;
        }

        ASN1Sequence seq = ASN1Sequence.getInstance(o);
        return new Builder()
            .setTime32(ASN1Integer.getInstance(seq.getObjectAt(0)))
            .setDuration(Duration.getInstance(seq.getObjectAt(1)))
            .createValidityPeriod();
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public ASN1Integer getTime32()
    {
        return time32;
    }

    public Duration getDuration()
    {
        return duration;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{time32, duration});
    }

    public static class Builder
    {

        private ASN1Integer time32;
        private Duration duration;

        public Builder setTime32(ASN1Integer time32)
        {
            this.time32 = time32;
            return this;
        }

        public Builder setDuration(Duration duration)
        {
            this.duration = duration;
            return this;
        }

        public ValidityPeriod createValidityPeriod()
        {
            return new ValidityPeriod(time32, duration);
        }
    }
}
