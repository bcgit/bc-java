package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.its.etsi102941.basetypes.CertificateFormat;
import org.bouncycastle.oer.its.etsi102941.basetypes.CertificateSubjectAttributes;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;

/**
 * SharedAtRequest ::= SEQUENCE {
 * eaId                          HashedId8,
 * keyTag                        OCTET STRING (SIZE(16)),
 * certificateFormat             CertificateFormat,
 * requestedSubjectAttributes    CertificateSubjectAttributes (WITH COMPONENTS{..., certIssuePermissions ABSENT}),
 * ...
 * }
 */
public class SharedAtRequest
    extends ASN1Object
{

    private final HashedId8 eaId;
    private final ASN1OctetString keyTag;
    private final CertificateFormat certificateFormat;
    private final CertificateSubjectAttributes requestedSubjectAttributes;

    public SharedAtRequest(
        HashedId8 eaId,
        ASN1OctetString keyTag,
        CertificateFormat certificateFormat,
        CertificateSubjectAttributes requestedSubjectAttributes)
    {
        this.eaId = eaId;
        this.keyTag = keyTag;
        this.certificateFormat = certificateFormat;
        this.requestedSubjectAttributes = requestedSubjectAttributes;
    }

    private SharedAtRequest(ASN1Sequence seq)
    {
        if (seq.size() != 4)
        {
            throw new IllegalArgumentException("expected sequence size of 4");
        }

        eaId = HashedId8.getInstance(seq.getObjectAt(0));
        keyTag = ASN1OctetString.getInstance(seq.getObjectAt(1));
        certificateFormat = CertificateFormat.getInstance(seq.getObjectAt(2));
        requestedSubjectAttributes = CertificateSubjectAttributes.getInstance(seq.getObjectAt(3));
    }

    public static SharedAtRequest getInstance(Object o)
    {
        if (o instanceof SharedAtRequest)
        {
            return (SharedAtRequest)o;
        }

        if (o != null)
        {
            return new SharedAtRequest(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public HashedId8 getEaId()
    {
        return eaId;
    }

    public ASN1OctetString getKeyTag()
    {
        return keyTag;
    }

    public CertificateFormat getCertificateFormat()
    {
        return certificateFormat;
    }

    public CertificateSubjectAttributes getRequestedSubjectAttributes()
    {
        return requestedSubjectAttributes;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{eaId, keyTag, certificateFormat, requestedSubjectAttributes});
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private HashedId8 eaId;
        private ASN1OctetString keyTag;
        private CertificateFormat certificateFormat;
        private CertificateSubjectAttributes requestedSubjectAttributes;

        public Builder setEaId(HashedId8 eaId)
        {
            this.eaId = eaId;
            return this;
        }

        public Builder setKeyTag(ASN1OctetString keyTag)
        {
            this.keyTag = keyTag;
            return this;
        }

        public Builder setKeyTag(byte[] keyTag)
        {
            this.keyTag = new DEROctetString(keyTag);
            return this;
        }

        public Builder setCertificateFormat(CertificateFormat certificateFormat)
        {
            this.certificateFormat = certificateFormat;
            return this;
        }

        public Builder setRequestedSubjectAttributes(CertificateSubjectAttributes requestedSubjectAttributes)
        {
            this.requestedSubjectAttributes = requestedSubjectAttributes;
            return this;
        }


        public SharedAtRequest createSharedAtRequest()
        {
            return new SharedAtRequest(eaId, keyTag, certificateFormat, requestedSubjectAttributes);
        }
    }

}
