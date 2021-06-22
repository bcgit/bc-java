package org.bouncycastle.oer.its.template;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.oer.OERDefinition;

import static org.bouncycastle.oer.OERDefinition.bitString;
import static org.bouncycastle.oer.OERDefinition.choice;
import static org.bouncycastle.oer.OERDefinition.enumItem;
import static org.bouncycastle.oer.OERDefinition.enumeration;
import static org.bouncycastle.oer.OERDefinition.extension;
import static org.bouncycastle.oer.OERDefinition.integer;
import static org.bouncycastle.oer.OERDefinition.nullValue;
import static org.bouncycastle.oer.OERDefinition.octets;
import static org.bouncycastle.oer.OERDefinition.optional;
import static org.bouncycastle.oer.OERDefinition.seq;
import static org.bouncycastle.oer.OERDefinition.seqof;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.CrlSeries;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.GeographicRegion;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.HashAlgorithm;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.HashId3;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.HashId8;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.PublicEncryptionKey;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.SequenceOfPsidSsp;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.Signature;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.SubjectAssurance;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.UINT8;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.ValidityPeriod;

/**
 * OER forward definition builders for OER encoded data.
 */
public class IEEE1609dot2
{
    /**
     * EndEntityType ::= BIT STRING {app (0), enrol (1) } (SIZE (8))
     */
    public static final OERDefinition.Builder EndEntityType =
        bitString(8).defaultValue(new DERBitString(new byte[]{0}, 0));

    /**
     * SubjectPermissions ::= CHOICE  {
     * explicit        SequenceOfPsidSspRange,
     * all             NULL,
     * ...
     * }
     */
    public static final OERDefinition.Builder SubjectPermissions = choice(
        Ieee1609Dot2BaseTypes.SequenceOfPsidSspRange, nullValue(), extension()
    ).label("SubjectPermissions");

    /**
     * VerificationKeyIndicator ::= CHOICE  {
     * verificationKey         PublicVerificationKey,
     * reconstructionValue     EccP256CurvePoint,
     * ...
     * }
     */
    public static final OERDefinition.Builder VerificationKeyIndicator = choice(
        Ieee1609Dot2BaseTypes.PublicVerificationKey,
        Ieee1609Dot2BaseTypes.EccP256CurvePoint,
        extension()).label("VerificationKeyIndicator");

    /**
     * PsidGroupPermissions ::= SEQUENCE  {
     * subjectPermissions SubjectPermissions,
     * minChainLength     INTEGER DEFAULT 1,
     * chainLengthRange   INTEGER DEFAULT 0,
     * eeType             EndEntityType DEFAULT '00'H
     * }
     */
    public static final OERDefinition.Builder PsidGroupPermissions = seq(
        SubjectPermissions, integer(1), integer(0), EndEntityType
    ).label("PsidGroupPermissions");
    
    /**
     * SequenceOfPsidGroupPermissions ::= SEQUENCE OF PsidGroupPermissions
     */
    public static final OERDefinition.Builder SequenceOfPsidGroupPermissions = seqof(PsidGroupPermissions).label("SequenceOfPsidGroupPermissions");

    /**
     * LinkageData ::= SEQUENCE  {
     * iCert                 IValue,
     * linkage-value         LinkageValue,
     * group-linkage-value   GroupLinkageValue OPTIONAL
     * }
     */
    public static final OERDefinition.Builder LinkageData = seq(
        Ieee1609Dot2BaseTypes.IValue,
        Ieee1609Dot2BaseTypes.LinkageValue,
        optional(Ieee1609Dot2BaseTypes.GroupLinkageValue),
        extension()
    ).label("LinkageData");

    /**
     * CertificateId ::= CHOICE  {
     * linkageData             LinkageData,
     * name                    Hostname,
     * binaryId                OCTET STRING(SIZE(1..64)),
     * none                    NULL,
     * ...
     * }
     */

    public static final OERDefinition.Builder CertificateId = choice(
        LinkageData,
        Ieee1609Dot2BaseTypes.Hostname,
        octets(1, 64).label("binaryId"),
        nullValue(), extension()
    ).label("CertificateId");


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

    public static final OERDefinition.Builder ToBeSignedCertificate = seq(
        CertificateId.labelPrefix("id"),
        HashId3.labelPrefix("cracaId"),
        CrlSeries.labelPrefix("crlSeries"),
        ValidityPeriod.labelPrefix("validityPeriod"),
        optional(
            GeographicRegion.labelPrefix("region"),
            SubjectAssurance.labelPrefix("assuranceLevel"),
            SequenceOfPsidSsp.labelPrefix("appPermissions"),
            SequenceOfPsidGroupPermissions.labelPrefix("certIssuePermissions"),
            SequenceOfPsidGroupPermissions.labelPrefix("certRequestPermissions"),
            nullValue().labelPrefix("canRequestRollover"),
            PublicEncryptionKey.labelPrefix("encryptionKey")),
        VerificationKeyIndicator.labelPrefix("verifyKeyIndicator"), extension()
    ).label("ToBeSignedCertificate");


    /**
     * IssuerIdentifier ::= CHOICE  {
     * sha256AndDigest         HashedId8,
     * self                    HashAlgorithm,
     * ...,
     * sha384AndDigest         HashedId8
     * }
     */
    public static final OERDefinition.Builder IssuerIdentifier = choice(HashId8, HashAlgorithm, extension(), HashId8).label("IssuerIdentifier");

    /**
     * CertificateType  ::= ENUMERATED  {
     * explicit,
     * implicit,
     * ...
     * }
     */
    public static final OERDefinition.Builder CertificateType = enumeration(enumItem("explicit"), enumItem("implicit"), extension()).label("CertificateType");

    /**
     * CertificateBase represents both of these, but with different values
     * depending on the type.
     * <p>
     * ExplicitCertificate ::= CertificateBase (WITH COMPONENTS {...,
     * type(explicit),
     * toBeSigned(WITH COMPONENTS {...,
     * verifyKeyIndicator(WITH COMPONENTS {verificationKey})
     * }),
     * signature PRESENT
     * })
     * <p>
     * ImplicitCertificate ::= CertificateBase (WITH COMPONENTS {...,
     * type(implicit),
     * toBeSigned(WITH COMPONENTS {...,
     * verifyKeyIndicator(WITH COMPONENTS {reconstructionValue})
     * }),
     * signature ABSENT
     * })
     * <p>
     * <p>
     * <p>
     * CertificateBase ::= SEQUENCE  {
     * version                 Uint8(3),
     * type                    CertificateType,
     * issuer                  IssuerIdentifier,
     * toBeSigned              ToBeSignedCertificate,
     * signature               Signature OPTIONAL
     * }
     */

    public static final OERDefinition.Builder CertificateBase = seq(UINT8, CertificateType, IssuerIdentifier, ToBeSignedCertificate, optional(Signature))
        .label("CertificateBase");

    /**
     * Certificate ::= CertificateBase (ImplicitCertificate | ExplicitCertificate)
     */
    public static final OERDefinition.Builder Certificate = CertificateBase.copy().label("Certificate(CertificateBase)");

    /**
     * Prebuilt certificate definition
     */
    public static final OERDefinition.Element certificate = Certificate.build();

    /**
     * Prebuilt TBS certificate definition
     */
    public static final OERDefinition.Element tbsCertificate = ToBeSignedCertificate.build();
}
