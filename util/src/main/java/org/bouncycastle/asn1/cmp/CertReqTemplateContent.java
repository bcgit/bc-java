package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.crmf.CertTemplate;

/**
 * GenMsg:    {id-it 19}, &lt; absent &gt;
 * GenRep:    {id-it 19}, CertReqTemplateContent | &lt; absent &gt;
 * <p>
 * CertReqTemplateValue  ::= CertReqTemplateContent
 * <p>
 * CertReqTemplateContent ::= SEQUENCE {
 * certTemplate           CertTemplate,
 * keySpec                Controls OPTIONAL }
 * <p>
 * Controls  ::= SEQUENCE SIZE (1..MAX) OF AttributeTypeAndValue
 */
public class CertReqTemplateContent
    extends ASN1Object
{
    private final CertTemplate certTemplate;
    private final ASN1Sequence keySpec;

    private CertReqTemplateContent(ASN1Sequence seq)
    {
        if (seq.size() != 1 && seq.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 1 or 2");
        }

        certTemplate = CertTemplate.getInstance(seq.getObjectAt(0));

        if (seq.size() > 1)
        {
            keySpec = ASN1Sequence.getInstance(seq.getObjectAt(1));
        }
        else
        {
            keySpec = null;
        }
    }


    public CertReqTemplateContent(CertTemplate certTemplate, ASN1Sequence keySpec)
    {
        this.certTemplate = certTemplate;
        this.keySpec = keySpec;
    }

    public static CertReqTemplateContent getInstance(Object o)
    {
        if (o instanceof CertReqTemplateContent)
        {
            return (CertReqTemplateContent)o;
        }
        else if (o != null)
        {
            return new CertReqTemplateContent(ASN1Sequence.getInstance(o));
        }

        return null;

    }

    public CertTemplate getCertTemplate()
    {
        return certTemplate;
    }


    public ASN1Sequence getKeySpec()
    {
        return keySpec;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(certTemplate);
        if (keySpec != null)
        {
            v.add(keySpec);
        }
        return new DERSequence(v);
    }
}
