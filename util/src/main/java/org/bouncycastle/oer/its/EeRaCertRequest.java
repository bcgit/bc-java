package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.OEROptional;

/**
 * EeRaCertRequest ::= SEQUENCE {
 * version           Uint8 (2),
 * generationTime    Time32,
 * type              CertificateType,
 * tbsCert           ToBeSignedCertificate (WITH COMPONENTS {
 * ...,
 * cracaId ('000000'H),
 * crlSeries (0),
 * appPermissions PRESENT,
 * certIssuePermissions ABSENT,
 * certRequestPermissions ABSENT,
 * verifyKeyIndicator (WITH COMPONENTS {
 * verificationKey
 * })
 * }),
 * additionalParams  AdditionalParams OPTIONAL,
 * ...
 * }
 */
public class EeRaCertRequest
    extends ASN1Object
{

    private final Uint8 version;
    private final Time32 generationTime;
    private final CertificateType type;
    private final ToBeSignedCertificate tbsCert;
    private final AdditionalParams additionalParams;


    public EeRaCertRequest(
        Uint8 version,
        Time32 generationTime,
        CertificateType type,
        ToBeSignedCertificate tbsCert,
        AdditionalParams additionalParams)
    {
        this.version = version;
        this.generationTime = generationTime;
        this.type = type;
        this.tbsCert = tbsCert;
        this.additionalParams = additionalParams;
    }

    public static EeRaCertRequest getInstance(Object o)
    {
        if (o instanceof EeRaCertRequest)
        {
            return (EeRaCertRequest)o;
        }

        ASN1Sequence seq = ASN1Sequence.getInstance(o);

        return new EeRaCertRequest(
            Uint8.getInstance(seq.getObjectAt(0)),
            Time32.getInstance(seq.getObjectAt(1)),
            CertificateType.getInstance(seq.getObjectAt(2)),
            ToBeSignedCertificate.getInstance(seq.getObjectAt(3)),
            OEROptional.getInstance(seq.getObjectAt(4)).getObject(AdditionalParams.class));

    }

    public static Builder builder()
    {
        return new Builder();
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

    public AdditionalParams getAdditionalParams()
    {
        return additionalParams;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return Utils.toSequence(version, generationTime, type, tbsCert, OEROptional.getInstance(additionalParams));
    }

    public static class Builder
    {
        private Uint8 version;
        private Time32 generationTime;
        private CertificateType type;
        private ToBeSignedCertificate tbsCert;
        private AdditionalParams additionalParams;

        public Builder setVersion(Uint8 version)
        {
            this.version = version;
            return this;
        }

        public Builder setGenerationTime(Time32 generationTime)
        {
            this.generationTime = generationTime;
            return this;
        }

        public Builder setType(CertificateType type)
        {
            this.type = type;
            return this;
        }

        public Builder setTbsCert(ToBeSignedCertificate tbsCert)
        {
            this.tbsCert = tbsCert;
            return this;
        }

        public Builder setAdditionalParams(AdditionalParams additionalParams)
        {
            this.additionalParams = additionalParams;
            return this;
        }

        public EeRaCertRequest createEeRaCertRequest()
        {
            return new EeRaCertRequest(version, generationTime, type, tbsCert, additionalParams);
        }
    }

}
