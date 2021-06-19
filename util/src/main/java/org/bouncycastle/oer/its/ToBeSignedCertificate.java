package org.bouncycastle.oer.its;

import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.OEROptional;

/**
 * <pre>
 *     ToBeSignedCertificate ::= SEQUENCE {
 *         id CertificateId,
 *         cracaId HashedId3,
 *         crlSeries CrlSeries,
 *         validityPeriod ValidityPeriod,
 *         region GeographicRegion OPTIONAL,
 *         assuranceLevel SubjectAssurance OPTIONAL,
 *         appPermissions SequenceOfPsidSep OPTIONAL,
 *         certIssuePermissions SequenceOfPsidGroupPermissions OPTIONAL,
 *         certRequestPermissions NULL OPTIONAL,
 *         encryptionKey PublicEncryptionKey OPTIONAL,
 *         verifyKeyIndicator VerificationKeyIndicator,
 *         ...
 *     }
 * </pre>
 */
public class ToBeSignedCertificate
    extends ASN1Object
{
    private final CertificateId certificateId;
    private final HashedId cracaId;
    private final CrlSeries crlSeries;
    private final ValidityPeriod validityPeriod;
    private final OEROptional geographicRegion;
    private final OEROptional assuranceLevel;
    private final OEROptional appPermissions;
    private final OEROptional certIssuePermissions;
    private final OEROptional certRequestPermissions;
    private final OEROptional canRequestRollover;
    private final OEROptional encryptionKey;
    private final VerificationKeyIndicator verificationKeyIndicator;


    public ToBeSignedCertificate(CertificateId certificateId,
                                 HashedId cracaId,
                                 CrlSeries crlSeries,
                                 ValidityPeriod validityPeriod,
                                 OEROptional geographicRegion,
                                 OEROptional assuranceLevel,
                                 OEROptional appPermissions,
                                 OEROptional certIssuePermissions,
                                 OEROptional certRequestPermissions,
                                 OEROptional canRequestRollover,
                                 OEROptional encryptionKey,
                                 VerificationKeyIndicator verificationKeyIndicator)
    {
        this.certificateId = certificateId;
        this.cracaId = cracaId;
        this.crlSeries = crlSeries;
        this.validityPeriod = validityPeriod;
        this.geographicRegion = geographicRegion;
        this.assuranceLevel = assuranceLevel;
        this.appPermissions = appPermissions;
        this.certIssuePermissions = certIssuePermissions;
        this.certRequestPermissions = certRequestPermissions;
        this.canRequestRollover = canRequestRollover;
        this.encryptionKey = encryptionKey;
        this.verificationKeyIndicator = verificationKeyIndicator;
    }

    public static ToBeSignedCertificate getInstance(Object o)
    {
        if (o == null || o instanceof ToBeSignedCertificate)
        {
            return (ToBeSignedCertificate)o;
        }

        Iterator<ASN1Encodable> seq = ASN1Sequence.getInstance(o).iterator();
        return new Builder()
            .setCertificateId(CertificateId.getInstance(seq.next()))
            .setCracaId(HashedId.getInstance(seq.next()))
            .setCrlSeries(CrlSeries.getInstance(seq.next()))
            .setValidityPeriod(ValidityPeriod.getInstance(seq.next()))
            .setGeographicRegion(OEROptional.getInstance(seq.next()))
            .setAssuranceLevel(OEROptional.getInstance(seq.next()))
            .setAppPermissions(OEROptional.getInstance(seq.next()))
            .setCertIssuePermissions(OEROptional.getInstance(seq.next()))
            .setCertRequestPermissions(OEROptional.getInstance(seq.next()))
            .setCanRequestRollover(OEROptional.getInstance(seq.next()))
            .setEncryptionKey(OEROptional.getInstance(seq.next()))
            .setVerificationKeyIndicator(VerificationKeyIndicator.getInstance(seq.next()))
            .createToBeSignedCertificate();

    }


    public CertificateId getCertificateId()
    {
        return certificateId;
    }

    public HashedId getCracaId()
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

    public GeographicRegion getGeographicRegion()
    {
        return geographicRegion.getObject(GeographicRegion.class);
    }

    public SubjectAssurance getAssuranceLevel()
    {
        return assuranceLevel.getObject(SubjectAssurance.class);
    }

    public SequenceOfPsidSsp getAppPermissions()
    {
        return appPermissions.getObject(SequenceOfPsidSsp.class);
    }

    public SequenceOfPsidGroupPermissions getCertIssuePermissions()
    {
        return certIssuePermissions.getObject(SequenceOfPsidGroupPermissions.class);
    }

    public ASN1Null getCertRequestPermissions()
    {
        return certRequestPermissions.getObject(ASN1Null.class);
    }

    public OEROptional getCanRequestRollover()
    {
        return canRequestRollover;
    }

    public PublicEncryptionKey getEncryptionKey()
    {
        return encryptionKey.getObject(PublicEncryptionKey.class);
    }

    public VerificationKeyIndicator getVerificationKeyIndicator()
    {
        return verificationKeyIndicator;
    }

    public ASN1Primitive toASN1Primitive()
    {

        /**
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
         */

        return Utils.toSequence(
            certificateId,
            cracaId,
            crlSeries,
            validityPeriod,
            geographicRegion,
            assuranceLevel,
            appPermissions,
            certIssuePermissions,
            certRequestPermissions,
            canRequestRollover,
            encryptionKey,
            verificationKeyIndicator);

    }


    public static class Builder
    {

        private CertificateId certificateId;
        private HashedId cracaId;
        private CrlSeries crlSeries;
        private ValidityPeriod validityPeriod;
        private OEROptional geographicRegion = OEROptional.ABSENT;
        private OEROptional assuranceLevel = OEROptional.ABSENT;
        private OEROptional appPermissions = OEROptional.ABSENT;
        private OEROptional certIssuePermissions = OEROptional.ABSENT;
        private OEROptional certRequestPermissions = OEROptional.ABSENT;
        private OEROptional canRequestRollover = OEROptional.ABSENT;
        private OEROptional encryptionKey = OEROptional.ABSENT;
        private VerificationKeyIndicator verificationKeyIndicator;


        public Builder setCertificateId(CertificateId certificateId)
        {
            this.certificateId = certificateId;
            return this;
        }

        public Builder setCracaId(HashedId cracaId)
        {
            this.cracaId = cracaId;
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

        public Builder setGeographicRegion(OEROptional geographicRegion)
        {
            this.geographicRegion = geographicRegion;
            return this;
        }

        public Builder setAssuranceLevel(OEROptional assuranceLevel)
        {
            this.assuranceLevel = assuranceLevel;
            return this;
        }

        public Builder setAppPermissions(OEROptional appPermissions)
        {
            this.appPermissions = appPermissions;
            return this;
        }

        public Builder setCertIssuePermissions(OEROptional certIssuePermissions)
        {
            this.certIssuePermissions = certIssuePermissions;
            return this;
        }

        public Builder setCertRequestPermissions(OEROptional certRequestPermissions)
        {
            this.certRequestPermissions = certRequestPermissions;
            return this;
        }

        public Builder setEncryptionKey(OEROptional encryptionKey)
        {
            this.encryptionKey = encryptionKey;
            return this;
        }

        public Builder setVerificationKeyIndicator(VerificationKeyIndicator verificationKeyIndicator)
        {
            this.verificationKeyIndicator = verificationKeyIndicator;
            return this;
        }

        public Builder setCanRequestRollover(OEROptional instance)
        {
            this.canRequestRollover = instance;
            return this;
        }

        public ToBeSignedCertificate createToBeSignedCertificate()
        {
            return new ToBeSignedCertificate(
                certificateId,
                cracaId,
                crlSeries,
                validityPeriod,
                geographicRegion,
                assuranceLevel,
                appPermissions,
                certIssuePermissions,
                certRequestPermissions,
                canRequestRollover,
                encryptionKey,
                verificationKeyIndicator);
        }


    }

}
