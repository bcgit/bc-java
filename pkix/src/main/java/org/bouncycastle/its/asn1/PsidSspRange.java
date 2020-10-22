package org.bouncycastle.its.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * PsidSspRange ::= SEQUENCE {
 * psid Psid,
 * sspRange SspRange OPTIONAL
 * }
 */
public class PsidSspRange
    extends ASN1Object
{
    private ASN1Integer psid;
    private SspRange sspRange;

    public PsidSspRange()
    {

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
            PsidSspRange psidSspRange = new PsidSspRange();
            if (seq.size() < 1 || seq.size() > 2)
            {
                throw new IllegalStateException("expected sequences with one or optionally two items");
            }

            if (seq.size() == 1)
            {
                psidSspRange.psid = (ASN1Integer)seq.getObjectAt(0);
            }
            if (seq.size() == 2)
            {
                psidSspRange.sspRange = SspRange.getInstance(seq.getObjectAt(1));
            }
            return psidSspRange;
        }
    }


    public ASN1Integer getPsid()
    {
        return psid;
    }

    public void setPsid(ASN1Integer psid)
    {
        this.psid = psid;
    }

    public SspRange getSspRange()
    {
        return sspRange;
    }

    public void setSspRange(SspRange sspRange)
    {
        this.sspRange = sspRange;
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
}
