package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.*;

import java.util.StringJoiner;

public class PolicyInformation
    extends ASN1Object
{
    private ASN1ObjectIdentifier   policyIdentifier;
    private ASN1Sequence          policyQualifiers;

    private PolicyInformation(
        ASN1Sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                    + seq.size());
        }

        policyIdentifier = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));

        if (seq.size() > 1)
        {
            policyQualifiers = ASN1Sequence.getInstance(seq.getObjectAt(1));
        }
    }

    public PolicyInformation(
        ASN1ObjectIdentifier policyIdentifier)
    {
        this.policyIdentifier = policyIdentifier;
    }

    public PolicyInformation(
        ASN1ObjectIdentifier policyIdentifier,
        ASN1Sequence        policyQualifiers)
    {
        this.policyIdentifier = policyIdentifier;
        this.policyQualifiers = policyQualifiers;
    }

    public static PolicyInformation getInstance(
        Object obj)
    {
        if (obj == null || obj instanceof PolicyInformation)
        {
            return (PolicyInformation)obj;
        }

        return new PolicyInformation(ASN1Sequence.getInstance(obj));
    }

    public ASN1ObjectIdentifier getPolicyIdentifier()
    {
        return policyIdentifier;
    }
    
    public ASN1Sequence getPolicyQualifiers()
    {
        return policyQualifiers;
    }
    
    /*
     * <pre>
     * PolicyInformation ::= SEQUENCE {
     *      policyIdentifier   CertPolicyId,
     *      policyQualifiers   SEQUENCE SIZE (1..MAX) OF
     *              PolicyQualifierInfo OPTIONAL }
     * </pre>
     */ 
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        
        v.add(policyIdentifier);

        if (policyQualifiers != null)
        {
            v.add(policyQualifiers);
        }
        
        return new DERSequence(v);
    }

    public String toString()
    {
        final StringBuilder sb = new StringBuilder();

        sb.append("Policy information: ");
        sb.append(policyIdentifier);

        if (policyQualifiers != null)
        {
            final StringJoiner joiner = new StringJoiner(", ", "[", "]");
            for (ASN1Encodable element : policyQualifiers)
            {
                joiner.add(String.valueOf(element));
            }
            sb.append(joiner);
        }

        return sb.toString();
    }
}
