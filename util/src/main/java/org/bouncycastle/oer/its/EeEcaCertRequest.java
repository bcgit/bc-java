package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.oer.OEROptional;

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
    private final Uint8 version;
    private final Time32 generationTime;
    private final CertificateType type;
    private final ToBeSignedCertificate tbsCert;
    private final ASN1IA5String canonicalId;

    public EeEcaCertRequest(
        Uint8 version,
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

    public static EeEcaCertRequest.Builder builder()
    {
        return new Builder();
    }

    public EeEcaCertRequest getInstance(Object o)
    {
        if (o instanceof EeEcaCertRequest)
        {
            return (EeEcaCertRequest)o;
        }
        ASN1Sequence seq = ASN1Sequence.getInstance(o);

        return new EeEcaCertRequest(
            Uint8.getInstance(seq.getObjectAt(0)),
            Time32.getInstance(seq.getObjectAt(1)),
            CertificateType.getInstance(seq.getObjectAt(2)),
            ToBeSignedCertificate.getInstance(seq.getObjectAt(3)),
            OEROptional.getInstance(seq.getObjectAt(4)).getObject(ASN1IA5String.class));
    }

    public ASN1Primitive toASN1Primitive()
    {
        return Utils.toSequence(version, generationTime, type, tbsCert, canonicalId);
    }

    public Uint8 getVersion()
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
        private Uint8 version;
        private Time32 generationTime;
        private CertificateType type;
        private ToBeSignedCertificate tbsCert;
        private DERIA5String canonicalId;

        public EeEcaCertRequest.Builder setVersion(Uint8 version)
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

        public EeEcaCertRequest createEeEcaCertRequest()
        {
            return new EeEcaCertRequest(version, generationTime, type, tbsCert, canonicalId);
        }
    }
}
