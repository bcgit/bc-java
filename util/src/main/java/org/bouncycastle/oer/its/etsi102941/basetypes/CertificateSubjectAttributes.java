package org.bouncycastle.oer.its.etsi102941.basetypes;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.ieee1609dot2.CertificateId;
import org.bouncycastle.oer.its.ieee1609dot2.SequenceOfPsidGroupPermissions;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.GeographicRegion;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SequenceOfPsidSsp;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SubjectAssurance;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.ValidityPeriod;


/**
 * CertificateSubjectAttributes ::= SEQUENCE {
 * id CertificateId OPTIONAL,
 * validityPeriod        ValidityPeriod OPTIONAL,
 * region                GeographicRegion OPTIONAL,
 * assuranceLevel        SubjectAssurance OPTIONAL,
 * appPermissions        SequenceOfPsidSsp OPTIONAL,
 * certIssuePermissions  SequenceOfPsidGroupPermissions OPTIONAL,
 * ...
 * }(WITH COMPONENTS { ..., appPermissions PRESENT} |
 * WITH COMPONENTS { ..., certIssuePermissions PRESENT})
 */
public class CertificateSubjectAttributes
    extends ASN1Object
{

    private final CertificateId id;
    private final ValidityPeriod validityPeriod;
    private final GeographicRegion region;
    private final SubjectAssurance assuranceLevel;
    private final SequenceOfPsidSsp appPermissions;
    private final SequenceOfPsidGroupPermissions certIssuePermissions;

    public CertificateSubjectAttributes(
        CertificateId id,
        ValidityPeriod validityPeriod,
        GeographicRegion region,
        SubjectAssurance assuranceLevel,
        SequenceOfPsidSsp appPermissions,
        SequenceOfPsidGroupPermissions certIssuePermissions)
    {
        this.id = id;
        this.validityPeriod = validityPeriod;
        this.region = region;
        this.assuranceLevel = assuranceLevel;
        this.appPermissions = appPermissions;
        this.certIssuePermissions = certIssuePermissions;
    }


    private CertificateSubjectAttributes(ASN1Sequence sequence)
    {
        if (sequence.size() != 6)
        {
            throw new IllegalArgumentException("expected sequence size of 6");
        }

        id = OEROptional.getValue(CertificateId.class, sequence.getObjectAt(0));
        validityPeriod = OEROptional.getValue(ValidityPeriod.class, sequence.getObjectAt(1));
        region = OEROptional.getValue(GeographicRegion.class, sequence.getObjectAt(2));
        assuranceLevel = OEROptional.getValue(SubjectAssurance.class, sequence.getObjectAt(3));
        appPermissions = OEROptional.getValue(SequenceOfPsidSsp.class, sequence.getObjectAt(4));
        certIssuePermissions = OEROptional.getValue(SequenceOfPsidGroupPermissions.class, sequence.getObjectAt(5));
    }

    public static CertificateSubjectAttributes getInstance(Object o)
    {
        if (o instanceof CertificateSubjectAttributes)
        {
            return (CertificateSubjectAttributes)o;
        }

        if (o != null)
        {
            return new CertificateSubjectAttributes(ASN1Sequence.getInstance(o));
        }

        return null;

    }


    public CertificateId getId()
    {
        return id;
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

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{
            OEROptional.getInstance(id),
            OEROptional.getInstance(validityPeriod),
            OEROptional.getInstance(region),
            OEROptional.getInstance(assuranceLevel),
            OEROptional.getInstance(appPermissions),
            OEROptional.getInstance(certIssuePermissions)
        });
    }
}
