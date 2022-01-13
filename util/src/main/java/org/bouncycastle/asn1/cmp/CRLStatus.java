package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Time;


/**
 * CRLStatus ::= SEQUENCE {
 * source       CRLSource,
 * thisUpdate   Time OPTIONAL }
 */
public class CRLStatus
    extends ASN1Object
{
    private final CRLSource source;
    private final Time time;

    private CRLStatus(ASN1Sequence sequence)
    {

        if (sequence.size() == 1 || sequence.size() == 2)
        {
            this.source = CRLSource.getInstance(sequence.getObjectAt(0));
            if (sequence.size() == 2)
            {
                this.time = Time.getInstance(sequence.getObjectAt(1));
            }
            else
            {
                this.time = null;
            }

        }
        else
        {
            throw new IllegalArgumentException("expected sequence size of 1 or 2, got " + sequence.size());
        }
    }

    public CRLStatus(CRLSource source, Time time)
    {
        this.source = source;
        this.time = time;
    }

    public static CRLStatus getInstance(Object o)
    {
        if (o instanceof CRLStatus)
        {
            return (CRLStatus)o;
        }
        else if (o != null)
        {
            return new CRLStatus(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public CRLSource getSource()
    {
        return source;
    }


    public Time getTime()
    {
        return time;
    }


    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(source);
        if (time != null)
        {
            v.add(time);
        }
        return new DERSequence(v);
    }
}
