package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.OEROptional;

/**
 * PsidSspRange ::= SEQUENCE {
 * psid Psid,
 * sspRange SspRange OPTIONAL
 * }
 */
public class PsidSspRange
    extends ASN1Object
{
    private final Psid psid;
    private final SspRange sspRange;

    public PsidSspRange(Psid psid, SspRange sspRange)
    {
        this.psid = psid;
        this.sspRange = sspRange;
    }


    private PsidSspRange(ASN1Sequence sequence)
    {
        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }

        this.psid = Psid.getInstance(sequence.getObjectAt(0));
        this.sspRange = OEROptional.getValue(SspRange.class, sequence.getObjectAt(1));
    }


    public static PsidSspRange getInstance(Object src)
    {
        if (src instanceof PsidSspRange)
        {
            return (PsidSspRange)src;
        }
        if (src != null)
        {
            return new PsidSspRange(ASN1Sequence.getInstance(src));
        }
        return null;

    }

    public Psid getPsid()
    {
        return psid;
    }

    public SspRange getSspRange()
    {
        return sspRange;
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{psid, OEROptional.getInstance(sspRange)});
    }

    public static class Builder
    {
        private Psid psid;
        private SspRange sspRange;

        public Builder setPsid(Psid psid)
        {
            this.psid = psid;
            return this;
        }

        public Builder setPsid(long psid)
        {
            this.psid = new Psid(psid);
            return this;
        }

        public Builder setSspRange(SspRange sspRange)
        {
            this.sspRange = sspRange;
            return this;
        }


        public PsidSspRange createPsidSspRange()
        {
            return new PsidSspRange(psid, sspRange);
        }

    }

}
