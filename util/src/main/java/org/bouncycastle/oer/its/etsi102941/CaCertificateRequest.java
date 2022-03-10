package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.its.etsi102941.basetypes.CertificateSubjectAttributes;
import org.bouncycastle.oer.its.etsi102941.basetypes.PublicKeys;

/**
 * CaCertificateRequest ::= SEQUENCE {
 * publicKeys                  PublicKeys,
 * requestedSubjectAttributes  CertificateSubjectAttributes,
 * ...
 * }
 */
public class CaCertificateRequest
    extends ASN1Object
{
    private final PublicKeys publicKeys;
    private final CertificateSubjectAttributes requestedSubjectAttributes;

    public CaCertificateRequest(PublicKeys publicKeys, CertificateSubjectAttributes requestedSubjectAttributes)
    {
        this.publicKeys = publicKeys;
        this.requestedSubjectAttributes = requestedSubjectAttributes;
    }

    private CaCertificateRequest(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        this.publicKeys = PublicKeys.getInstance(seq.getObjectAt(0));
        this.requestedSubjectAttributes = CertificateSubjectAttributes.getInstance(seq.getObjectAt(1));
    }

    public static CaCertificateRequest getInstance(Object o)
    {
        if (o instanceof CaCertificateRequest)
        {
            return (CaCertificateRequest)o;
        }
        if (o != null)
        {
            return new CaCertificateRequest(ASN1Sequence.getInstance(o));
        }

        return null;
    }


    public PublicKeys getPublicKeys()
    {
        return publicKeys;
    }

    public CertificateSubjectAttributes getRequestedSubjectAttributes()
    {
        return requestedSubjectAttributes;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{publicKeys, requestedSubjectAttributes});
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private PublicKeys publicKeys;
        private CertificateSubjectAttributes requestedSubjectAttributes;

        public Builder setPublicKeys(PublicKeys publicKeys)
        {
            this.publicKeys = publicKeys;
            return this;
        }

        public Builder setRequestedSubjectAttributes(CertificateSubjectAttributes requestedSubjectAttributes)
        {
            this.requestedSubjectAttributes = requestedSubjectAttributes;
            return this;
        }

        public CaCertificateRequest createCaCertificateRequest()
        {
            return new CaCertificateRequest(publicKeys, requestedSubjectAttributes);
        }

    }

}
