package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

public class Validity
    extends ASN1Object
{
    public static Validity getInstance(Object obj)
    {
        if (obj instanceof Validity)
        {
            return (Validity)obj;
        }
        else if (obj != null)
        {
            return new Validity(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static Validity getInstance(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return new Validity(ASN1Sequence.getInstance(taggedObject, declaredExplicit));
    }

    private final Time notBefore;
    private final Time notAfter;

    private Validity(ASN1Sequence seq)
    {
        int count = seq.size();
        if (count != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + count);
        }

        this.notBefore = Time.getInstance(seq.getObjectAt(0));
        this.notAfter = Time.getInstance(seq.getObjectAt(1));
    }

    public Validity(Time notBefore, Time notAfter)
    {
        if (notBefore == null)
        {
            throw new NullPointerException("'notBefore' cannot be null");
        }
        if (notAfter == null)
        {
            throw new NullPointerException("'notAfter' cannot be null");
        }

        this.notBefore = notBefore;
        this.notAfter = notAfter;
    }

    public Time getNotBefore()
    {
        return notBefore;
    }

    public Time getNotAfter()
    {
        return notAfter;
    }

    /**
     * <pre>
     * Validity ::= SEQUENCE {
     *   notBefore      Time,
     *   notAfter       Time  }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(notBefore, notAfter);
    }
}
