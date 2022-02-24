package org.bouncycastle.oer.its.ieee1609dot2dot1;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.ItsUtils;
import org.bouncycastle.oer.its.ieee1609dot2.CertificateType;
import org.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Time32;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT8;

/**
 * EeEcaCertRequest ::= SEQUENCE {
 * version         Uint8 (2),
 * generationTime  Time32,
 * type            CertificateType,
 * tbsCert         ToBeSignedCertificate (WITH COMPONENTS {
 * ...,
 * id (WITH COMPONENTS {
 * ...,
 * linkageData ABSENT
 * }),
 * cracaId ('000000'H),
 * crlSeries (0),
 * appPermissions ABSENT,
 * certIssuePermissions ABSENT,
 * certRequestPermissions PRESENT,
 * verifyKeyIndicator (WITH COMPONENTS {
 * verificationKey
 * })
 * }),
 * canonicalId     IA5String OPTIONAL,
 * ...
 * }
 */
public class EeEcaCertRequest
    extends ASN1Object
{
    private final UINT8 version;
    private final Time32 generationTime;
    private final CertificateType type;
    private final ToBeSignedCertificate tbsCert;
    private final ASN1IA5String canonicalId;

    public EeEcaCertRequest(
        UINT8 version,
        Time32 generationTime,
        CertificateType type,
        ToBeSignedCertificate tbsCert,
        ASN1IA5String canonicalId)
    {
        this.version = version;
        this.generationTime = generationTime;
        this.type = type;
        this.tbsCert = tbsCert;
        this.canonicalId = canonicalId;
    }

    private EeEcaCertRequest(ASN1Sequence seq)
    {
        if (seq.size() != 5)
        {
            throw new IllegalArgumentException("expected sequence size of 5");
        }

        version = UINT8.getInstance(seq.getObjectAt(0));
        generationTime = Time32.getInstance(seq.getObjectAt(1));
        type = CertificateType.getInstance(seq.getObjectAt(2));
        tbsCert = ToBeSignedCertificate.getInstance(seq.getObjectAt(3));
        canonicalId = OEROptional.getInstance(seq.getObjectAt(4)).getObject(ASN1IA5String.class);

    }

    public static EeEcaCertRequest.Builder builder()
    {
        return new Builder();
    }

    public static EeEcaCertRequest getInstance(Object o)
    {
        if (o instanceof EeEcaCertRequest)
        {
            return (EeEcaCertRequest)o;
        }

        if (o != null)
        {
            return new EeEcaCertRequest(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(
            version,
            generationTime,
            type,
            tbsCert,
            OEROptional.getInstance(canonicalId));
    }

    public UINT8 getVersion()
    {
        return version;
    }

    public Time32 getGenerationTime()
    {
        return generationTime;
    }

    public CertificateType getType()
    {
        return type;
    }

    public ToBeSignedCertificate getTbsCert()
    {
        return tbsCert;
    }

    public ASN1IA5String getCanonicalId()
    {
        return canonicalId;
    }

    public static class Builder
    {
        private UINT8 version;
        private Time32 generationTime;
        private CertificateType type;
        private ToBeSignedCertificate tbsCert;
        private DERIA5String canonicalId;

        public EeEcaCertRequest.Builder setVersion(UINT8 version)
        {
            this.version = version;
            return this;
        }

        public EeEcaCertRequest.Builder setGenerationTime(Time32 generationTime)
        {
            this.generationTime = generationTime;
            return this;
        }

        public EeEcaCertRequest.Builder setType(CertificateType type)
        {
            this.type = type;
            return this;
        }

        public EeEcaCertRequest.Builder setTbsCert(ToBeSignedCertificate tbsCert)
        {
            this.tbsCert = tbsCert;
            return this;
        }

        public EeEcaCertRequest.Builder setCanonicalId(DERIA5String canonicalId)
        {
            this.canonicalId = canonicalId;
            return this;
        }

        public EeEcaCertRequest.Builder setCanonicalId(String canonicalId)
        {
            this.canonicalId = new DERIA5String(canonicalId);
            return this;
        }


        public EeEcaCertRequest createEeEcaCertRequest()
        {
            return new EeEcaCertRequest(version, generationTime, type, tbsCert, canonicalId);
        }
    }
}
