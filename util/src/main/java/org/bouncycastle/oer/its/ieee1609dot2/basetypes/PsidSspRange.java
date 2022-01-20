package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
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
    private final ASN1Integer psid;
    private final OEROptional sspRange;

    public PsidSspRange(ASN1Integer psid, OEROptional sspRange)
    {
        this.psid = psid;
        this.sspRange = sspRange;
    }

    public PsidSspRange(ASN1Integer psid, SspRange sspRange)
    {
        this.psid = psid;
        this.sspRange = OEROptional.getInstance(sspRange);
    }

    public static PsidSspRange getInstance(Object src)
    {
        if (src == null)
        {
            return null;
        }
        else if (src instanceof PsidSspRange)
        {
            return (PsidSspRange)src;
        }
        else
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(src);
            return new PsidSspRange(
                ASN1Integer.getInstance(seq.getObjectAt(0)),
                OEROptional.getInstance(seq.getObjectAt(1)));
        }
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public ASN1Integer getPsid()
    {
        return psid;
    }

    public OEROptional getSspRange()
    {
        return sspRange;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector avec = new ASN1EncodableVector();
        avec.add(psid);
        if (sspRange != null)
        {
            avec.add(sspRange);
        }
        return new DERSequence(avec);
    }

    public static class Builder
    {
        private ASN1Integer psid;
        private OEROptional sspRange = OEROptional.ABSENT;

        public Builder setPsid(ASN1Integer psid)
        {
            this.psid = psid;
            return this;
        }

        public Builder setPsid(long psid)
        {
            this.psid = new ASN1Integer(psid);
            return this;
        }


        public Builder setSspRange(SspRange sspRange)
        {
            this.sspRange = OEROptional.getInstance(sspRange);
            return this;
        }


        public PsidSspRange createPsidSspRange()
        {
            return new PsidSspRange(psid, sspRange);
        }

    }

}
