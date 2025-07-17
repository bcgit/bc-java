package org.bouncycastle.asn1.crmf;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Time;

public class OptionalValidity
    extends ASN1Object
{
    public static OptionalValidity getInstance(Object o)
    {
        if (o instanceof OptionalValidity)
        {
            return (OptionalValidity)o;
        }

        if (o != null)
        {
            return new OptionalValidity(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public static OptionalValidity getInstance(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return new OptionalValidity(ASN1Sequence.getInstance(taggedObject, declaredExplicit));
    }

    public static OptionalValidity getTagged(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return new OptionalValidity(ASN1Sequence.getTagged(taggedObject, declaredExplicit));
    }

    private Time notBefore;
    private Time notAfter;

    private OptionalValidity(ASN1Sequence seq)
    {
        Enumeration en = seq.getObjects();
        while (en.hasMoreElements())
        {
            ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

            if (tObj.getTagNo() == 0)
            {
                notBefore = Time.getInstance(tObj, true); // CHOICE
            }
            else
            {
                notAfter = Time.getInstance(tObj, true); // CHOICE
            }
        }

        // TODO[crmf] Validate the "at least one" rule after parsing?
    }

    public OptionalValidity(Time notBefore, Time notAfter)
    {
        if (notBefore == null && notAfter == null)
        {
            throw new IllegalArgumentException("at least one of notBefore/notAfter MUST be present.");
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
     * OptionalValidity ::= SEQUENCE {
     *     notBefore    [0] Time OPTIONAL,
     *     notAfter     [1] Time OPTIONAL } --at least one MUST be present
     *
     * Time ::= CHOICE { ... }
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        if (notBefore != null)
        {
            v.add(new DERTaggedObject(true, 0, notBefore)); // CHOICE
        }

        if (notAfter != null)
        {
            v.add(new DERTaggedObject(true, 1, notAfter)); // CHOICE
        }

        return new DERSequence(v);
    }
}
