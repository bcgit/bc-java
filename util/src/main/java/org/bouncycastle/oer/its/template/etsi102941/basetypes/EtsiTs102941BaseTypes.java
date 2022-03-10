package org.bouncycastle.oer.its.template.etsi102941.basetypes;

import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.its.template.etsi103097.EtsiTs103097Module;
import org.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;
import org.bouncycastle.oer.its.template.ieee1609dot2.basetypes.Ieee1609Dot2BaseTypes;


public class EtsiTs102941BaseTypes
{
    /**
     * CertificateFormat::= INTEGER {
     * ts103097v131 (1)
     * }(1..255)
     */
    public static final OERDefinition.Builder CertificateFormat = OERDefinition.integer(0, 255).typeName("CertificateFormat");


    /**
     * CertificateSubjectAttributes ::= SEQUENCE {
     * id                   CertificateId OPTIONAL,
     * validityPeriod       ValidityPeriod OPTIONAL,
     * region               GeographicRegion OPTIONAL,
     * assuranceLevel       SubjectAssurance OPTIONAL,
     * appPermissions       SequenceOfPsidSsp OPTIONAL,
     * certIssuePermissions  SequenceOfPsidGroupPermissions OPTIONAL,
     * ...
     * }(WITH COMPONENTS { ..., appPermissions PRESENT} |
     * WITH COMPONENTS { ..., certIssuePermissions PRESENT})
     */
    public static final OERDefinition.Builder CertificateSubjectAttributes = OERDefinition.seq(
        OERDefinition.optional(
            IEEE1609dot2.CertificateId.label("id"),
            Ieee1609Dot2BaseTypes.ValidityPeriod.label("validityPeriod"),
            Ieee1609Dot2BaseTypes.GeographicRegion.label("region"),
            Ieee1609Dot2BaseTypes.SubjectAssurance.label("assuranceLevel"),
            Ieee1609Dot2BaseTypes.SequenceOfPsidSsp.label("appPermissions"),
            IEEE1609dot2.SequenceOfPsidGroupPermissions.label("certIssuePermissions"),
            OERDefinition.extension()
        )
    ).typeName("CertificateSubjectAttributes");

    /**
     * EcSignature::= CHOICE {
     * encryptedEcSignature EtsiTs103097Data-Encrypted{EtsiTs103097Data-SignedExternalPayload},
     * ecSignature   EtsiTs103097Data-SignedExternalPayload
     * }
     */
    public static final OERDefinition.Builder EcSignature = OERDefinition.choice(
        EtsiTs103097Module.EtsiTs103097Data_Encrypted.label("encryptedEcSignature"),
        EtsiTs103097Module.EtsiTs103097Data_SignedExternalPayload.label("ecSignature")
    ).typeName("EcSignature");

    /**
     * PublicKeys ::= SEQUENCE {
     * verificationKey PublicVerificationKey,
     * encryptionKey   PublicEncryptionKey OPTIONAL
     * }
     */
    public static final OERDefinition.Builder PublicKeys = OERDefinition.seq(
        Ieee1609Dot2BaseTypes.PublicVerificationKey.label("verificationKey"),
        OERDefinition.optional(Ieee1609Dot2BaseTypes.PublicEncryptionKey.label("encryptionKey"))
    ).typeName("PublicKeys");

    /**
     * Version ::= INTEGER {v1(1)}
     */
    public static final OERDefinition.Builder Version = OERDefinition.integer(0, 255).typeName("Version");

}
