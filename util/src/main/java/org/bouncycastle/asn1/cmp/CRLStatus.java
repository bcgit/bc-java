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
    private final Time thisUpdate;

    private CRLStatus(ASN1Sequence sequence)
    {
        if (sequence.size() == 1 || sequence.size() == 2)
        {
            this.source = CRLSource.getInstance(sequence.getObjectAt(0));
            if (sequence.size() == 2)
            {
                this.thisUpdate = Time.getInstance(sequence.getObjectAt(1));
            }
            else
            {
                this.thisUpdate = null;
            }
        }
        else
        {
            throw new IllegalArgumentException("expected sequence size of 1 or 2, got " + sequence.size());
        }
    }

    public CRLStatus(CRLSource source, Time thisUpdate)
    {
        this.source = source;
        this.thisUpdate = thisUpdate;
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

    public Time getThisUpdate()
    {
        return thisUpdate;
    }

    /**
     * @deprecated Use {@link #getThisUpdate()} instead.
     */
    public Time getTime()
    {
        return thisUpdate;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(source);
        if (thisUpdate != null)
        {
            v.add(thisUpdate);
        }
        return new DERSequence(v);
    }
}
