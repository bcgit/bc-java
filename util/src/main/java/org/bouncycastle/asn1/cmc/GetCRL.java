package org.bouncycastle.asn1.cmc;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.ReasonFlags;

/**
 * <pre>
 * id-cmc-getCRL OBJECT IDENTIFIER ::= {id-cmc 16}
 *
 * GetCRL ::= SEQUENCE {
 *    issuerName    Name,
 *    cRLName       GeneralName OPTIONAL,
 *    time          GeneralizedTime OPTIONAL,
 *    reasons       ReasonFlags OPTIONAL }
 * </pre>
 */
public class GetCRL
    extends ASN1Object
{
    private final X500Name issuerName;
    private GeneralName cRLName;
    private ASN1GeneralizedTime time;
    private ReasonFlags reasons;

    public GetCRL(X500Name issuerName, GeneralName cRLName, ASN1GeneralizedTime time, ReasonFlags reasons)
    {
        this.issuerName = issuerName;
        this.cRLName = cRLName;
        this.time = time;
        this.reasons = reasons;
    }


    private GetCRL(ASN1Sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 4)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.issuerName = X500Name.getInstance(seq.getObjectAt(0));

        int index = 1;
        if (seq.size() > index && seq.getObjectAt(index).toASN1Primitive() instanceof ASN1TaggedObject)
        {
            this.cRLName = GeneralName.getInstance(seq.getObjectAt(index++));
        }
        if (seq.size() > index && seq.getObjectAt(index).toASN1Primitive() instanceof ASN1GeneralizedTime)
        {
            this.time = ASN1GeneralizedTime.getInstance(seq.getObjectAt(index++));
        }
        if (seq.size() > index && seq.getObjectAt(index).toASN1Primitive() instanceof DERBitString)
        {
            this.reasons = new ReasonFlags(DERBitString.getInstance(seq.getObjectAt(index)));
        }
    }

    public static GetCRL getInstance(Object o)
    {
        if (o instanceof GetCRL)
        {
            return (GetCRL)o;
        }

        if (o != null)
        {
            return new GetCRL(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public X500Name getIssuerName()
    {
        return issuerName;
    }

    public GeneralName getcRLName()
    {
        return cRLName;
    }

    public ASN1GeneralizedTime getTime()
    {
        return time;
    }

    public ReasonFlags getReasons()
    {
        return reasons;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(4);

        v.add(issuerName);
        if (cRLName != null)
        {
            v.add(cRLName);
        }
        if (time != null)
        {
            v.add(time);
        }
        if (reasons != null)
        {
            v.add(reasons);
        }

        return new DERSequence(v);
    }
}
