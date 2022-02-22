package org.bouncycastle.oer.its.ieee1609dot2;

import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.ItsUtils;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.CrlSeries;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.GeographicRegion;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId3;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicEncryptionKey;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SequenceOfPsidSsp;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SubjectAssurance;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.ValidityPeriod;

/**
 * <pre>
 *     ToBeSignedCertificate ::= SEQUENCE {
 *     id                      CertificateId,
 *     cracaId                 HashedId3,
 *     crlSeries               CrlSeries,
 *     validityPeriod          ValidityPeriod,
 *     region                  GeographicRegion OPTIONAL,
 *     assuranceLevel          SubjectAssurance OPTIONAL,
 *     appPermissions          SequenceOfPsidSsp OPTIONAL,
 *     certIssuePermissions    SequenceOfPsidGroupPermissions OPTIONAL,
 *     certRequestPermissions  SequenceOfPsidGroupPermissions OPTIONAL,
 *     canRequestRollover      NULL OPTIONAL,
 *     encryptionKey           PublicEncryptionKey OPTIONAL,
 *     verifyKeyIndicator      VerificationKeyIndicator,
 *     ...
 *   }
 *   (WITH COMPONENTS { ..., appPermissions PRESENT} |
 *    WITH COMPONENTS { ..., certIssuePermissions PRESENT} |
 *    WITH COMPONENTS { ..., certRequestPermissions PRESENT})
 * </pre>
 */
public class ToBeSignedCertificate
    extends ASN1Object
{
    private final CertificateId id;
    private final HashedId3 cracaId;
    private final CrlSeries crlSeries;
    private final ValidityPeriod validityPeriod;
    private final GeographicRegion region;
    private final SubjectAssurance assuranceLevel;
    private final SequenceOfPsidSsp appPermissions;
    private final SequenceOfPsidGroupPermissions certIssuePermissions;
    private final SequenceOfPsidGroupPermissions certRequestPermissions;
    private final ASN1Null canRequestRollover;
    private final PublicEncryptionKey encryptionKey;
    private final VerificationKeyIndicator verifyKeyIndicator;


    public ToBeSignedCertificate(CertificateId certificateId,
                                 HashedId3 cracaId,
                                 CrlSeries crlSeries,
                                 ValidityPeriod validityPeriod,
                                 GeographicRegion geographicRegion,
                                 SubjectAssurance assuranceLevel,
                                 SequenceOfPsidSsp appPermissions,
                                 SequenceOfPsidGroupPermissions certIssuePermissions,
                                 SequenceOfPsidGroupPermissions certRequestPermissions,
                                 ASN1Null canRequestRollover,
                                 PublicEncryptionKey encryptionKey,
                                 VerificationKeyIndicator verificationKeyIndicator)
    {
        this.id = certificateId;
        this.cracaId = cracaId;
        this.crlSeries = crlSeries;
        this.validityPeriod = validityPeriod;
        this.region = geographicRegion;
        this.assuranceLevel = assuranceLevel;
        this.appPermissions = appPermissions;
        this.certIssuePermissions = certIssuePermissions;
        this.certRequestPermissions = certRequestPermissions;
        this.canRequestRollover = canRequestRollover;
        this.encryptionKey = encryptionKey;
        this.verifyKeyIndicator = verificationKeyIndicator;
    }


    private ToBeSignedCertificate(ASN1Sequence sequence)
    {

        Iterator<ASN1Encodable> seq = ASN1Sequence.getInstance(sequence).iterator();

        if (sequence.size() != 12)
        {
            throw new IllegalArgumentException("expected sequence size of 12");
        }

        id = CertificateId.getInstance(seq.next());
        cracaId = HashedId3.getInstance(seq.next());
        crlSeries = CrlSeries.getInstance(seq.next());
        validityPeriod = ValidityPeriod.getInstance(seq.next());
        region = OEROptional.getValue(GeographicRegion.class, seq.next());
        assuranceLevel = OEROptional.getValue(SubjectAssurance.class, seq.next());
        appPermissions = OEROptional.getValue(SequenceOfPsidSsp.class, seq.next());
        certIssuePermissions = OEROptional.getValue(SequenceOfPsidGroupPermissions.class, seq.next());
        certRequestPermissions = OEROptional.getValue(SequenceOfPsidGroupPermissions.class, seq.next());
        canRequestRollover = OEROptional.getValue(ASN1Null.class, seq.next());
        encryptionKey = OEROptional.getValue(PublicEncryptionKey.class, seq.next());
        verifyKeyIndicator = VerificationKeyIndicator.getInstance(seq.next());
    }


    public static ToBeSignedCertificate getInstance(Object o)
    {
        if (o instanceof ToBeSignedCertificate)
        {
            return (ToBeSignedCertificate)o;
        }

        if (o != null)
        {
            return new ToBeSignedCertificate(ASN1Sequence.getInstance(o));
        }

        return null;

    }


    public CertificateId getId()
    {
        return id;
    }

    public HashedId3 getCracaId()
    {
        return cracaId;
    }

    public CrlSeries getCrlSeries()
    {
        return crlSeries;
    }

    public ValidityPeriod getValidityPeriod()
    {
        return validityPeriod;
    }

    public GeographicRegion getRegion()
    {
        return region;
    }

    public SubjectAssurance getAssuranceLevel()
    {
        return assuranceLevel;
    }

    public SequenceOfPsidSsp getAppPermissions()
    {
        return appPermissions;
    }

    public SequenceOfPsidGroupPermissions getCertIssuePermissions()
    {
        return certIssuePermissions;
    }

    public SequenceOfPsidGroupPermissions getCertRequestPermissions()
    {
        return certRequestPermissions;
    }

    public ASN1Null getCanRequestRollover()
    {
        return canRequestRollover;
    }

    public PublicEncryptionKey getEncryptionKey()
    {
        return encryptionKey;
    }

    public VerificationKeyIndicator getVerifyKeyIndicator()
    {
        return verifyKeyIndicator;
    }

    /**
     * <pre>
     * ToBeSignedCertificate ::= SEQUENCE  {
     * id                     CertificateId,
     * cracaId                HashedId3,
     * crlSeries              CrlSeries,
     * validityPeriod         ValidityPeriod,
     * region                 GeographicRegion OPTIONAL,
     * assuranceLevel         SubjectAssurance OPTIONAL,
     * appPermissions         SequenceOfPsidSsp OPTIONAL,
     * certIssuePermissions   SequenceOfPsidGroupPermissions OPTIONAL,
     * certRequestPermissions SequenceOfPsidGroupPermissions OPTIONAL,
     * canRequestRollover     NULL OPTIONAL,
     * encryptionKey          PublicEncryptionKey OPTIONAL,
     * verifyKeyIndicator     VerificationKeyIndicator,
     * ...
     * }
     * (WITH COMPONENTS { ..., appPermissions PRESENT} |
     * WITH COMPONENTS { ..., certIssuePermissions PRESENT} |
     * WITH COMPONENTS { ..., certRequestPermissions PRESENT})
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(
            id,
            cracaId,
            crlSeries,
            validityPeriod,
            OEROptional.getInstance(region),
            OEROptional.getInstance(assuranceLevel),
            OEROptional.getInstance(appPermissions),
            OEROptional.getInstance(certIssuePermissions),
            OEROptional.getInstance(certRequestPermissions),
            OEROptional.getInstance(canRequestRollover),
            OEROptional.getInstance(encryptionKey),
            verifyKeyIndicator);
    }


    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private CertificateId id;
        private HashedId3 cracaId;
        private CrlSeries crlSeries;
        private ValidityPeriod validityPeriod;
        private GeographicRegion region;
        private SubjectAssurance assuranceLevel;
        private SequenceOfPsidSsp appPermissions;
        private SequenceOfPsidGroupPermissions certIssuePermissions;
        private SequenceOfPsidGroupPermissions certRequestPermissions;
        private ASN1Null canRequestRollover;
        private PublicEncryptionKey encryptionKey;
        private VerificationKeyIndicator verifyKeyIndicator;

        public Builder()
        {
        }

        public Builder(Builder o)
        {
            this.id = o.id;
            this.cracaId = o.cracaId;
            this.crlSeries = o.crlSeries;
            this.validityPeriod = o.validityPeriod;
            this.region = o.region;
            this.assuranceLevel = o.assuranceLevel;
            this.appPermissions = o.appPermissions;
            this.certIssuePermissions = o.certIssuePermissions;
            this.certRequestPermissions = o.certRequestPermissions;
            this.canRequestRollover = o.canRequestRollover;
            this.encryptionKey = o.encryptionKey;
            this.verifyKeyIndicator = o.verifyKeyIndicator;
        }

        public Builder(ToBeSignedCertificate o)
        {
            this.id = o.id;
            this.cracaId = o.cracaId;
            this.crlSeries = o.crlSeries;
            this.validityPeriod = o.validityPeriod;
            this.region = o.region;
            this.assuranceLevel = o.assuranceLevel;
            this.appPermissions = o.appPermissions;
            this.certIssuePermissions = o.certIssuePermissions;
            this.certRequestPermissions = o.certRequestPermissions;
            this.canRequestRollover = o.canRequestRollover;
            this.encryptionKey = o.encryptionKey;
            this.verifyKeyIndicator = o.verifyKeyIndicator;
        }


        public Builder setId(CertificateId id)
        {
            this.id = id;
            return this;
        }

        public Builder setCracaId(HashedId3 cracaId)
        {
            this.cracaId = (HashedId3)cracaId;
            return this;
        }

        public Builder setCrlSeries(CrlSeries crlSeries)
        {
            this.crlSeries = crlSeries;
            return this;
        }

        public Builder setValidityPeriod(ValidityPeriod validityPeriod)
        {
            this.validityPeriod = validityPeriod;
            return this;
        }

        public Builder setRegion(GeographicRegion region)
        {
            this.region = region;
            return this;
        }

        public Builder setAssuranceLevel(SubjectAssurance assuranceLevel)
        {
            this.assuranceLevel = assuranceLevel;
            return this;
        }

        public Builder setAppPermissions(SequenceOfPsidSsp appPermissions)
        {
            this.appPermissions = appPermissions;
            return this;
        }

        public Builder setCertIssuePermissions(SequenceOfPsidGroupPermissions certIssuePermissions)
        {
            this.certIssuePermissions = certIssuePermissions;
            return this;
        }

        public Builder setCertRequestPermissions(SequenceOfPsidGroupPermissions certRequestPermissions)
        {
            this.certRequestPermissions = certRequestPermissions;
            return this;
        }

        public Builder setCanRequestRollover()
        {
            this.canRequestRollover = DERNull.INSTANCE;
            return this;
        }

        public Builder setEncryptionKey(PublicEncryptionKey encryptionKey)
        {
            this.encryptionKey = encryptionKey;
            return this;
        }

        public Builder setVerifyKeyIndicator(VerificationKeyIndicator verifyKeyIndicator)
        {
            this.verifyKeyIndicator = verifyKeyIndicator;
            return this;
        }

        public ToBeSignedCertificate createToBeSignedCertificate()
        {
            return new ToBeSignedCertificate(
                id,
                cracaId,
                crlSeries,
                validityPeriod,
                region,
                assuranceLevel,
                appPermissions,
                certIssuePermissions,
                certRequestPermissions,
                canRequestRollover,
                encryptionKey,
                verifyKeyIndicator);
        }
    }
}
