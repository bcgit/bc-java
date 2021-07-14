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
import static org.bouncycastle.oer.OERDefinition.opaque;
import static org.bouncycastle.oer.OERDefinition.optional;
import static org.bouncycastle.oer.OERDefinition.seq;
import static org.bouncycastle.oer.OERDefinition.seqof;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.CrlSeries;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.EciesP256EncryptedKey;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.EncryptionKey;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.GeographicRegion;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.HashAlgorithm;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.HashedId3;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.HashedId8;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.Psid;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.PublicEncryptionKey;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.SequenceOfHashedId3;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.SequenceOfPsidSsp;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.Signature;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.SubjectAssurance;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.ThreeDLocation;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.Time64;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.UINT8;
import static org.bouncycastle.oer.its.template.Ieee1609Dot2BaseTypes.ValidityPeriod;

/**
 * OER forward definition builders for OER encoded data.
 */
public class IEEE1609dot2
{

    /**
     * PduFunctionalType ::= INTEGER (0..255)
     * tlsHandshake          PduFunctionalType ::= 1
     * iso21177ExtendedAuth  PduFunctionalType ::= 2
     */
    public static final OERDefinition.Builder PduFunctionalType = integer(0, 255);


    /**
     * HashedData::= CHOICE {
     * sha256HashedData  OCTET STRING (SIZE(32)),
     * ...,
     * sha384HashedData  OCTET STRING (SIZE(48)),
     * reserved          OCTET STRING (SIZE(32))
     * }
     */
    public static final OERDefinition.Builder HashedData = choice(
        octets(32).label("sha256HashedData"),
        extension(),
        octets(48).label("sha384HashedData"),
        octets(32).label("reserved")
    );

    /**
     * MissingCrlIdentifier ::= SEQUENCE {
     * cracaId    HashedId3,
     * crlSeries  CrlSeries,
     * ...
     * }
     */
    public static final OERDefinition.Builder MissingCrlIdentifier = seq(
        HashedId3.label("cracaId"),
        CrlSeries.label("crlSeries"),
        extension()
    );


    /**
     * HeaderInfoContributorId ::= INTEGER (0..255)
     * etsiHeaderInfoContributorId         HeaderInfoContributorId ::= 2
     */

    public static final OERDefinition.Builder HeaderInfoContributorId = integer(0, 255);


    /**
     * Ieee1609Dot2HeaderInfoContributedExtensions
     * IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION ::= {
     * {EtsiOriginatingHeaderInfoExtension IDENTIFIED BY etsiHeaderInfoContributorId},
     * ...
     * }
     */
    public static final OERDefinition.Builder EtsiOriginatingHeaderInfoExtension = seq(
        HeaderInfoContributorId.label("id"),
        extension()
    );

    /**
     * ContributedExtensionBlock ::= SEQUENCE {
     * contributorId IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION.
     * &id({Ieee1609Dot2HeaderInfoContributedExtensions}),
     * extns   SEQUENCE (SIZE(1..MAX)) OF IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION.
     * &Extn({Ieee1609Dot2HeaderInfoContributedExtensions}{@.contributorId})
     * }
     */
    public static final OERDefinition.Builder ContributedExtensionBlock = seq(
        HeaderInfoContributorId,
        seqof(EtsiOriginatingHeaderInfoExtension)
    );


    /**
     * IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION ::= CLASS {
     *       &id    HeaderInfoContributorId UNIQUE,
     *       &Extn
     *   } WITH SYNTAX {&Extn IDENTIFIED BY &id}
     */


    /**
     * PreSharedKeyRecipientInfo ::= HashedId8
     */
    public static final OERDefinition.Builder PreSharedKeyRecipientInfo = HashedId8;


    /**
     * EncryptedDataEncryptionKey ::= CHOICE {
     * eciesNistP256         EciesP256EncryptedKey,
     * eciesBrainpoolP256r1  EciesP256EncryptedKey,
     * ...
     * }
     */
    public static final OERDefinition.Builder EncryptedDataEncryptionKey = choice(
        EciesP256EncryptedKey.label("eciesNistP256"),
        EciesP256EncryptedKey.label("eciesBrainpoolP256r1"),
        extension()
    );

    /**
     * PKRecipientInfo ::= SEQUENCE {
     * recipientId  HashedId8,
     * encKey       EncryptedDataEncryptionKey
     * }
     */
    public static final OERDefinition.Builder PKRecipientInfo = seq(
        HashedId8.label("recipientId"),
        EncryptedDataEncryptionKey.label("encKey")
    );


    /**
     * AesCcmCiphertext ::= SEQUENCE {
     * nonce          OCTET STRING (SIZE (12)),
     * ccmCiphertext  Opaque
     * }
     */
    public static final OERDefinition.Builder AesCcmCiphertext = seq(
        octets(12).label("nonce"),
        opaque().label("ccmCiphertext")
    );


    /**
     * SymmetricCiphertext ::= CHOICE {
     * aes128ccm  AesCcmCiphertext,
     * ...
     * }
     */
    public static final OERDefinition.Builder SymmetricCiphertext = choice(
        AesCcmCiphertext.label("aes128ccm"),
        extension()
    );


    /**
     * SymmRecipientInfo ::= SEQUENCE {
     * recipientId  HashedId8,
     * encKey       SymmetricCiphertext
     * }
     */
    public static final OERDefinition.Builder SymmRecipientInfo = seq(
        HashedId8.label("recipientId"),
        SymmetricCiphertext.label("encKey")
    );

    /**
     * RecipientInfo ::= CHOICE {
     * pskRecipInfo         PreSharedKeyRecipientInfo,
     * symmRecipInfo        SymmRecipientInfo,
     * certRecipInfo        PKRecipientInfo,
     * signedDataRecipInfo  PKRecipientInfo,
     * rekRecipInfo         PKRecipientInfo
     * }
     */
    public static final OERDefinition.Builder RecipientInfo = choice(
        PreSharedKeyRecipientInfo.label("pskRecipInfo"),
        SymmRecipientInfo.label("symmRecipInfo"),
        PKRecipientInfo.label("certRecipInfo"),
        PKRecipientInfo.label("signedDataRecipInfo"),
        PKRecipientInfo.label("rekRecipInfo")
    );

    /**
     * SequenceOfRecipientInfo ::= SEQUENCE OF RecipientInfo
     */
    public static final OERDefinition.Builder SequenceOfRecipientInfo = seqof(
        RecipientInfo
    );

    /**
     * EncryptedData ::= SEQUENCE {
     * recipients  SequenceOfRecipientInfo,
     * ciphertext  SymmetricCiphertext
     * }
     */
    public static final OERDefinition.Builder EncryptedData = seq(
        SequenceOfRecipientInfo.label("recipients"),
        SymmetricCiphertext.label("ciphertext")
    );


    /**
     * Countersignature ::= Ieee1609Dot2Data (WITH COMPONENTS {...,
     * content (WITH COMPONENTS {...,
     * signedData  (WITH COMPONENTS {...,
     * tbsData (WITH COMPONENTS {...,
     * payload (WITH COMPONENTS {...,
     * data ABSENT,
     * extDataHash PRESENT
     * }),
     * headerInfo(WITH COMPONENTS {...,
     * generationTime PRESENT,
     * expiryTime ABSENT,
     * generationLocation ABSENT,
     * p2pcdLearningRequest ABSENT,
     * missingCrlIdentifier ABSENT,
     * encryptionKey ABSENT
     * })
     * })
     * })
     * })
     * })
     */


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
        HashedId3.labelPrefix("cracaId"),
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
    public static final OERDefinition.Builder IssuerIdentifier = choice(HashedId8, HashAlgorithm, extension(), HashedId8).label("IssuerIdentifier");

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
     * SequenceOfCertificate ::= SEQUENCE OF Certificate
     */
    public static final OERDefinition.Builder SequenceOfCertificate = seqof(Certificate);


    /**
     * HeaderInfo ::= SEQUENCE {
     * psid                  Psid,
     * generationTime        Time64 OPTIONAL,
     * expiryTime            Time64  OPTIONAL,
     * generationLocation    ThreeDLocation OPTIONAL,
     * p2pcdLearningRequest  HashedId3 OPTIONAL,
     * missingCrlIdentifier  MissingCrlIdentifier OPTIONAL,
     * encryptionKey         EncryptionKey OPTIONAL,
     * ...,
     * inlineP2pcdRequest    SequenceOfHashedId3 OPTIONAL,
     * requestedCertificate  Certificate OPTIONAL,
     * pduFunctionalType     PduFunctionalType OPTIONAL,
     * contributedExtensions ContributedExtensionBlocks OPTIONAL
     * }
     */
    public static final OERDefinition.Builder HeaderInfo = seq(
        Psid.label("psid"),
        optional(
            Time64.label("generationTime"),
            Time64.label("expiryTime"),
            ThreeDLocation.label("generationLocation"),
            HashedId3.label("p2pcdLearningRequest"),
            MissingCrlIdentifier.label("missingCrlIdentifier"),
            EncryptionKey.label("encryptionKey")
        ), extension(),
        optional(
            SequenceOfHashedId3.label("inlineP2pcdRequest"),
            Certificate.label("requestedCertificate"),
            PduFunctionalType.label("pduFunctionalType"),
            ContributedExtensionBlock.label("contributedExtensions")

        )
    );


    /**
     * SignerIdentifier ::= CHOICE {
     * digest       HashedId8,
     * certificate  SequenceOfCertificate,
     * self         NULL,
     * ...
     * }
     */
    public static final OERDefinition.Builder SignerIdentifier = choice(HashedId8.label("digest"), SequenceOfCertificate, nullValue().label("self"), extension());

    public static final OERDefinition.Builder ToBeSignedData = new OERDefinition.MutableBuilder(OERDefinition.BaseType.SEQ);


    /**
     * SignedData ::= SEQUENCE {
     * hashId     HashAlgorithm,
     * tbsData    ToBeSignedData,
     * signer     SignerIdentifier,
     * signature  Signature
     * }
     */
    public static final OERDefinition.Builder SignedData = seq(
        HashAlgorithm.label("hashId"),
        ToBeSignedData.label("tbsData"),
        SignerIdentifier.label("signer"),
        Signature.label("signature"));

    /**
     * Ieee1609Dot2Content ::=  CHOICE {
     * unsecuredData             Opaque,
     * signedData                SignedData,
     * encryptedData             EncryptedData,
     * signedCertificateRequest  Opaque,
     * ...
     * }
     */
    public static final OERDefinition.Builder Ieee1609Dot2Content = choice(

        opaque().label("unsecuredData"),
        SignedData.label("signedData"),
        EncryptedData.label("encryptedData"),
        opaque().label("signedCertificateRequest"),
        extension());


    public static final OERDefinition.Builder Countersignature = seq(
        UINT8.label("protocolVersion"),
        Ieee1609Dot2Content.label("content")
    );

    /**
     * Ieee1609Dot2Data ::= SEQUENCE {
     * protocolVersion  Uint8(3),
     * content          Ieee1609Dot2Content
     * }
     */
    public static final OERDefinition.Builder Ieee1609Dot2Data = seq(
        UINT8.label("protocolVersion"),
        Ieee1609Dot2Content.label("content"));

    /**
     * SignedDataPayload ::= SEQUENCE {
     * data         Ieee1609Dot2Data OPTIONAL,
     * extDataHash  HashedData OPTIONAL,
     * ...
     * } (WITH COMPONENTS {..., data PRESENT} |
     * WITH COMPONENTS {..., extDataHash PRESENT})
     */
    public static final OERDefinition.Builder SignedDataPayload = seq(
        optional(Ieee1609Dot2Data.label("data"),
            HashedData.label("extDataHash")),
        extension());


    /**
     * ToBeSignedData ::= SEQUENCE {
     * payload     SignedDataPayload,
     * headerInfo  HeaderInfo
     * }
     */
//    public static final OERDefinition.Builder ToBeSignedData = seq(
//        SignedDataPayload.label("payload"),
//        HeaderInfo.label("headerInfo"));


    /**
     * Prebuilt certificate definition
     */
    public static final OERDefinition.Element certificate = Certificate.build();

    /**
     * Prebuilt TBS certificate definition
     */
    public static final OERDefinition.Element tbsCertificate = ToBeSignedCertificate.build();

    static
    {
        ((OERDefinition.MutableBuilder)ToBeSignedData).addItemsAndFreeze(SignedDataPayload.label("payload"),
            HeaderInfo.label("headerInfo"));
    }
}
