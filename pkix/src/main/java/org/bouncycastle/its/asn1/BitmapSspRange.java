package org.bouncycastle.its.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class BitmapSspRange
    extends ASN1Object
{
    private ASN1OctetString sspValue;
    private ASN1OctetString sspBitmask;


    public static BitmapSspRange getInstance(Object src) {
        if (src == null) {
            return null;
        } else if (src instanceof BitmapSspRange) {
            return (BitmapSspRange)src;
        } else if (src instanceof  ASN1Sequence) {
            if (((ASN1Sequence)src).size() != 2) {
                throw new IllegalStateException("expected sequence with jValue and value");
            }
            BitmapSspRange bssr = new BitmapSspRange();
            bssr.sspValue = (ASN1OctetString)((ASN1Sequence)src).getObjectAt(0);
            bssr.sspBitmask = (ASN1OctetString)((ASN1Sequence)src).getObjectAt(1);
            return bssr;
        } else {
            return getInstance(ASN1Sequence.getInstance(src));
        }
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector avec = new ASN1EncodableVector();
        avec.add(sspValue);
        avec.add(sspBitmask);
        return new DERSequence(avec);
    }


    public ASN1OctetString getSspValue()
    {
        return sspValue;
    }

    public void setSspValue(ASN1OctetString sspValue)
    {
        this.sspValue = sspValue;
    }

    public ASN1OctetString getSspBitmask()
    {
        return sspBitmask;
    }

    public void setSspBitmask(ASN1OctetString sspBitmask)
    {
        this.sspBitmask = sspBitmask;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }
        if (!super.equals(o))
        {
            return false;
        }

        BitmapSspRange that = (BitmapSspRange)o;

        if (sspValue != null ? !sspValue.equals(that.sspValue) : that.sspValue != null)
        {
            return false;
        }
        return sspBitmask != null ? sspBitmask.equals(that.sspBitmask) : that.sspBitmask == null;
    }

    @Override
    public int hashCode()
    {
        int result = super.hashCode();
        result = 31 * result + (sspValue != null ? sspValue.hashCode() : 0);
        result = 31 * result + (sspBitmask != null ? sspBitmask.hashCode() : 0);
        return result;
    }
}
