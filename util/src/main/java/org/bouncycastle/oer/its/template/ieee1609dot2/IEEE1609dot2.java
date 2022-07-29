package org.bouncycastle.oer.its.template.ieee1609dot2;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.oer.Element;
import org.bouncycastle.oer.ElementSupplier;
import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.Switch;
import org.bouncycastle.oer.SwitchIndexer;
import org.bouncycastle.oer.its.template.etsi103097.extension.EtsiTs103097ExtensionModule;
import org.bouncycastle.oer.its.template.ieee1609dot2.basetypes.Ieee1609Dot2BaseTypes;
import org.bouncycastle.util.BigIntegers;

/**
 * OER forward definition builders for OER encoded data.
 */
public class IEEE1609dot2
{

    public static final OERDefinition.Builder Opaque = OERDefinition.octets().typeName("Opaque");


    /**
     * PduFunctionalType ::= INTEGER (0..255)
     * tlsHandshake          PduFunctionalType ::= 1
     * iso21177ExtendedAuth  PduFunctionalType ::= 2
     */
    public static final OERDefinition.Builder PduFunctionalType = OERDefinition.integer(0, 255).typeName("PduFunctionalType");


    /**
     * HashedData::= CHOICE {
     * sha256HashedData  OCTET STRING (SIZE(32)),
     * ...,
     * sha384HashedData  OCTET STRING (SIZE(48)),
     * reserved          OCTET STRING (SIZE(32))
     * }
     */
    public static final OERDefinition.Builder HashedData = OERDefinition.choice(
        OERDefinition.octets(32).label("sha256HashedData"),
        OERDefinition.extension(
            OERDefinition.octets(48).label("sha384HashedData"),
            OERDefinition.octets(32).label("reserved")
        )
    ).typeName("HashedData");

    /**
     * MissingCrlIdentifier ::= SEQUENCE {
     * cracaId    HashedId3,
     * crlSeries  CrlSeries,
     * ...
     * }
     */
    public static final OERDefinition.Builder MissingCrlIdentifier = OERDefinition.seq(
        Ieee1609Dot2BaseTypes.HashedId3.label("cracaId"),
        Ieee1609Dot2BaseTypes.CrlSeries.label("crlSeries"),
        OERDefinition.extension()
    ).typeName("MissingCrlIdentifier");


    /**
     * etsiHeaderInfoContributorId         HeaderInfoContributorId ::= 2
     */
    private static final ASN1Integer etsiHeaderInfoContributorId = new ASN1Integer(BigIntegers.TWO);
    private static final ASN1Encodable[] extensionBlockSwitchKeys = new ASN1Encodable[]{etsiHeaderInfoContributorId};

    /**
     * HeaderInfoContributorId ::= INTEGER (0..255)
     * etsiHeaderInfoContributorId         HeaderInfoContributorId ::= 2
     */

    public static final OERDefinition.Builder HeaderInfoContributorId = OERDefinition.integer(0, 255)
        .typeName("HeaderInfoContributorId").validSwitchValue(etsiHeaderInfoContributorId);


    /**
     * Switch for ContributedExtensionBlock
     */
    public static final Switch ContributedExtensionBlockSwitch = new Switch()
    {

        public ASN1Encodable[] keys()
        {
            return extensionBlockSwitchKeys;
        }

        public Element result(SwitchIndexer indexer)
        {
            ASN1Integer type = ASN1Integer.getInstance(indexer.get(0).toASN1Primitive());

            if (type.equals(etsiHeaderInfoContributorId))
            {
                return OERDefinition.seqof(EtsiTs103097ExtensionModule.EtsiOriginatingHeaderInfoExtension).rangeToMAXFrom(1).label("extns").build();
            }

            //
            // We got here because the header extension value is unknown.
            //
            throw new IllegalArgumentException("No forward definition for type id " + type);
        }

    };

    /**
     * IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION ::= CLASS {
     * &amp;id    HeaderInfoContributorId UNIQUE,
     * &amp;Extn
     * } WITH SYNTAX {&amp;Extn IDENTIFIED BY &amp;id}
     * <p>
     * ContributedExtensionBlock ::= SEQUENCE {
     * contributorId IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION.
     * &amp;id({Ieee1609Dot2HeaderInfoContributedExtensions}),
     * extns   SEQUENCE (SIZE(1..MAX)) OF IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION.
     * &amp;Extn({Ieee1609Dot2HeaderInfoContributedExtensions}{&#64;.contributorId})
     * }
     */
    public static final OERDefinition.Builder ContributedExtensionBlock = OERDefinition.seq(
        HeaderInfoContributorId.label("contributorId"),
        OERDefinition.aSwitch(ContributedExtensionBlockSwitch).label("Extn")
    ).typeName("ContributedExtensionBlock");


    /**
     * ContributedExtensionBlocks ::= SEQUENCE (SIZE(1..MAX)) OF ContributedExtensionBlock
     */
    public static final OERDefinition.Builder ContributedExtensionBlocks =
        OERDefinition.seqof(ContributedExtensionBlock).rangeToMAXFrom(1).typeName("ContributedExtensionBlocks");

    /**
     * PreSharedKeyRecipientInfo ::= HashedId8
     */
    public static final OERDefinition.Builder PreSharedKeyRecipientInfo = Ieee1609Dot2BaseTypes.HashedId8.typeName("PreSharedKeyRecipientInfo");


    /**
     * EncryptedDataEncryptionKey ::= CHOICE {
     * eciesNistP256         EciesP256EncryptedKey,
     * eciesBrainpoolP256r1  EciesP256EncryptedKey,
     * ...
     * }
     */
    public static final OERDefinition.Builder EncryptedDataEncryptionKey = OERDefinition.choice(
        Ieee1609Dot2BaseTypes.EciesP256EncryptedKey.label("eciesNistP256"),
        Ieee1609Dot2BaseTypes.EciesP256EncryptedKey.label("eciesBrainpoolP256r1"),
        OERDefinition.extension()
    ).typeName("EncryptedDataEncryptionKey");

    /**
     * PKRecipientInfo ::= SEQUENCE {
     * recipientId  HashedId8,
     * encKey       EncryptedDataEncryptionKey
     * }
     */
    public static final OERDefinition.Builder PKRecipientInfo = OERDefinition.seq(
        Ieee1609Dot2BaseTypes.HashedId8.label("recipientId"),
        EncryptedDataEncryptionKey.label("encKey")
    ).typeName("PKRecipientInfo");


    /**
     * AesCcmCiphertext ::= SEQUENCE {
     * nonce          OCTET STRING (SIZE (12)),
     * ccmCiphertext  Opaque
     * }
     */
    public static final OERDefinition.Builder AesCcmCiphertext = OERDefinition.seq(
        OERDefinition.octets(12).label("nonce"),
        Opaque.label("ccmCiphertext")
    ).typeName("AesCcmCiphertext");


    /**
     * SymmetricCiphertext ::= CHOICE {
     * aes128ccm  AesCcmCiphertext,
     * ...
     * }
     */
    public static final OERDefinition.Builder SymmetricCiphertext = OERDefinition.choice(
        AesCcmCiphertext.label("aes128ccm"),
        OERDefinition.extension()
    ).typeName("SymmetricCiphertext");


    /**
     * SymmRecipientInfo ::= SEQUENCE {
     * recipientId  HashedId8,
     * encKey       SymmetricCiphertext
     * }
     */
    public static final OERDefinition.Builder SymmRecipientInfo = OERDefinition.seq(
        Ieee1609Dot2BaseTypes.HashedId8.label("recipientId"),
        SymmetricCiphertext.label("encKey")
    ).typeName("SymmRecipientInfo");

    /**
     * RecipientInfo ::= CHOICE {
     * pskRecipInfo         PreSharedKeyRecipientInfo,
     * symmRecipInfo        SymmRecipientInfo,
     * certRecipInfo        PKRecipientInfo,
     * signedDataRecipInfo  PKRecipientInfo,
     * rekRecipInfo         PKRecipientInfo
     * }
     */
    public static final OERDefinition.Builder RecipientInfo = OERDefinition.choice(
        PreSharedKeyRecipientInfo.label("pskRecipInfo"),
        SymmRecipientInfo.label("symmRecipInfo"),
        PKRecipientInfo.label("certRecipInfo"),
        PKRecipientInfo.label("signedDataRecipInfo"),
        PKRecipientInfo.label("rekRecipInfo")
    ).typeName("RecipientInfo");

    /**
     * SequenceOfRecipientInfo ::= SEQUENCE OF RecipientInfo
     */
    public static final OERDefinition.Builder SequenceOfRecipientInfo = OERDefinition.seqof(
        RecipientInfo
    ).typeName("SequenceOfRecipientInfo");

    /**
     * EncryptedData ::= SEQUENCE {
     * recipients  SequenceOfRecipientInfo,
     * ciphertext  SymmetricCiphertext
     * }
     */
    public static final OERDefinition.Builder EncryptedData = OERDefinition.seq(
        SequenceOfRecipientInfo.label("recipients"),
        SymmetricCiphertext.label("ciphertext")
    ).typeName("EncryptedData");


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
        OERDefinition.bitString(8).defaultValue(new DERBitString(new byte[]{0}, 0))
            .typeName("EndEntityType");

    /**
     * SubjectPermissions ::= CHOICE  {
     * explicit        SequenceOfPsidSspRange,
     * all             NULL,
     * ...
     * }
     */
    public static final OERDefinition.Builder SubjectPermissions = OERDefinition.choice(
        Ieee1609Dot2BaseTypes.SequenceOfPsidSspRange.label("explicit"),
        OERDefinition.nullValue().label("all"),
        OERDefinition.extension()
    ).typeName("SubjectPermissions");

    /**
     * VerificationKeyIndicator ::= CHOICE  {
     * verificationKey         PublicVerificationKey,
     * reconstructionValue     EccP256CurvePoint,
     * ...
     * }
     */
    public static final OERDefinition.Builder VerificationKeyIndicator = OERDefinition.choice(
        Ieee1609Dot2BaseTypes.PublicVerificationKey.label("verificationKey"),
        Ieee1609Dot2BaseTypes.EccP256CurvePoint.label("reconstructionValue"),
        OERDefinition.extension()
    ).typeName("VerificationKeyIndicator");

    /**
     * PsidGroupPermissions ::= SEQUENCE  {
     * subjectPermissions SubjectPermissions,
     * minChainLength     INTEGER DEFAULT 1,
     * chainLengthRange   INTEGER DEFAULT 0,
     * eeType             EndEntityType DEFAULT '00'H
     * }
     */
    public static final OERDefinition.Builder PsidGroupPermissions = OERDefinition.seq(
        SubjectPermissions.label("subjectPermissions"),
        OERDefinition.integer(1).label("minChainLength"),
        OERDefinition.integer(0).label("chainLengthRange"),
        EndEntityType.label("eeType")
    ).typeName("PsidGroupPermissions");

    /**
     * SequenceOfPsidGroupPermissions ::= SEQUENCE OF PsidGroupPermissions
     */
    public static final OERDefinition.Builder SequenceOfPsidGroupPermissions =
        OERDefinition.seqof(PsidGroupPermissions).typeName("SequenceOfPsidGroupPermissions");

    /**
     * LinkageData ::= SEQUENCE  {
     * iCert                 IValue,
     * linkage-value         LinkageValue,
     * group-linkage-value   GroupLinkageValue OPTIONAL
     * }
     */
    public static final OERDefinition.Builder LinkageData = OERDefinition.seq(
        Ieee1609Dot2BaseTypes.IValue.label("iCert"),
        Ieee1609Dot2BaseTypes.LinkageValue.label("linkageValue"),
        OERDefinition.optional(Ieee1609Dot2BaseTypes.GroupLinkageValue.label("groupLinkageValue")),
        OERDefinition.extension()
    ).typeName("LinkageData");

    /**
     * CertificateId ::= CHOICE  {
     * linkageData             LinkageData,
     * name                    Hostname,
     * binaryId                OCTET STRING(SIZE(1..64)),
     * none                    NULL,
     * ...
     * }
     */

    public static final OERDefinition.Builder CertificateId = OERDefinition.choice(
        LinkageData.label("linkageData"),
        Ieee1609Dot2BaseTypes.Hostname.label("name"),
        OERDefinition.octets(1, 64).label("binaryId"),
        OERDefinition.nullValue().label("none"),
        OERDefinition.extension()
    ).typeName("CertificateId");


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

    public static final OERDefinition.Builder ToBeSignedCertificate = OERDefinition.seq(
        CertificateId.label("id"),
        Ieee1609Dot2BaseTypes.HashedId3.label("cracaId"),
        Ieee1609Dot2BaseTypes.CrlSeries.label("crlSeries"),
        Ieee1609Dot2BaseTypes.ValidityPeriod.label("validityPeriod"),
        OERDefinition.optional(
            Ieee1609Dot2BaseTypes.GeographicRegion.label("region"),
            Ieee1609Dot2BaseTypes.SubjectAssurance.label("assuranceLevel"),
            Ieee1609Dot2BaseTypes.SequenceOfPsidSsp.label("appPermissions"),
            SequenceOfPsidGroupPermissions.label("certIssuePermissions"),
            SequenceOfPsidGroupPermissions.label("certRequestPermissions"),
            OERDefinition.nullValue().label("canRequestRollover"),
            Ieee1609Dot2BaseTypes.PublicEncryptionKey.label("encryptionKey")),
        VerificationKeyIndicator.label("verifyKeyIndicator"),
        OERDefinition.extension()
    ).typeName("ToBeSignedCertificate");
    /**
     * IssuerIdentifier ::= CHOICE  {
     * sha256AndDigest         HashedId8,
     * self                    HashAlgorithm,
     * ...,
     * sha384AndDigest         HashedId8
     * }
     */
    public static final OERDefinition.Builder IssuerIdentifier = OERDefinition.choice(
        Ieee1609Dot2BaseTypes.HashedId8.label("sha256AndDigest"),
        Ieee1609Dot2BaseTypes.HashAlgorithm.label("self"),
        OERDefinition.extension(
            Ieee1609Dot2BaseTypes.HashedId8.label("sha384AndDigest"))
    ).typeName("IssuerIdentifier");


    /**
     * CertificateType  ::= ENUMERATED  {
     * explicit,
     * implicit,
     * ...
     * }
     */
    public static final OERDefinition.Builder CertificateType = OERDefinition.enumeration(
            OERDefinition.enumItem("explicit"),
            OERDefinition.enumItem("implicit"),
            OERDefinition.extension())
        .typeName("CertificateType");

    private static ASN1Integer explicitOrdinal = new ASN1Integer(BigInteger.ZERO);
    private static ASN1Integer implicitOrdinal = new ASN1Integer(BigInteger.ONE);


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

    public static final OERDefinition.Builder CertificateBase = OERDefinition.seq(
            Ieee1609Dot2BaseTypes.UINT8.label("version"),
            CertificateType.label("type"),
            IssuerIdentifier.label("issuer"),
            ToBeSignedCertificate.label("toBeSigned"),
            OERDefinition.optional(Ieee1609Dot2BaseTypes.Signature.label("signature"))).label("signature")
        .typeName("CertificateBase");
    /**
     * Certificate ::= CertificateBase (ImplicitCertificate | ExplicitCertificate)
     */
    public static final OERDefinition.Builder Certificate = CertificateBase.copy().typeName("Certificate");


    /**
     * ExplicitCertificate ::= CertificateBase (WITH COMPONENTS {...,
     * type(explicit),
     * toBeSigned(WITH COMPONENTS {...,
     * verifyKeyIndicator(WITH COMPONENTS {verificationKey})
     * }),
     * signature PRESENT
     * })
     */
    public static final OERDefinition.Builder ExplicitCertificate =
        CertificateBase.typeName("ExplicitCertificate")
            .replaceChild(1, CertificateType.validSwitchValue(explicitOrdinal).label("type"));

    /**
     * ImplicitCertificate ::= CertificateBase (WITH COMPONENTS {...,
     * type(implicit),
     * toBeSigned(WITH COMPONENTS {...,
     * verifyKeyIndicator(WITH COMPONENTS {reconstructionValue})
     * }),
     * signature ABSENT
     * })
     */
    public static final OERDefinition.Builder ImplicitCertificate =
        CertificateBase.typeName("ImplicitCertificate")
            .replaceChild(1, CertificateType.validSwitchValue(implicitOrdinal).label("type"));

    /**
     * SequenceOfCertificate ::= SEQUENCE OF Certificate
     */
    public static final OERDefinition.Builder SequenceOfCertificate = OERDefinition.seqof(Certificate).typeName("SequenceOfCertificate");

    /**
     * SignerIdentifier ::= CHOICE {
     * digest       HashedId8,
     * certificate  SequenceOfCertificate,
     * self         NULL,
     * ...
     * }
     */
    public static final OERDefinition.Builder SignerIdentifier = OERDefinition.choice(
        Ieee1609Dot2BaseTypes.HashedId8.label("digest"),
        SequenceOfCertificate.label("certificate"),
        OERDefinition.nullValue().label("self"),
        OERDefinition.extension()
    ).typeName("SignerIdentifier");


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
    public static final OERDefinition.Builder HeaderInfo = OERDefinition.seq(
        Ieee1609Dot2BaseTypes.Psid.label("psid"),
        OERDefinition.optional(
            Ieee1609Dot2BaseTypes.Time64.label("generationTime"),
            Ieee1609Dot2BaseTypes.Time64.label("expiryTime"),
            Ieee1609Dot2BaseTypes.ThreeDLocation.label("generationLocation"),
            Ieee1609Dot2BaseTypes.HashedId3.label("p2pcdLearningRequest"),
            MissingCrlIdentifier.label("missingCrlIdentifier"),
            Ieee1609Dot2BaseTypes.EncryptionKey.label("encryptionKey")
        ), OERDefinition.extension(
            OERDefinition.optional(
                Ieee1609Dot2BaseTypes.SequenceOfHashedId3.label("inlineP2pcdRequest"),
                Certificate.label("requestedCertificate"),
                PduFunctionalType.label("pduFunctionalType"),
                ContributedExtensionBlocks.label("contributedExtensions")
            )
        )
    ).typeName("HeaderInfo");


    /**
     * ToBeSignedData ::= SEQUENCE {
     * payload     SignedDataPayload,
     * headerInfo  HeaderInfo
     * }
     * Defined in static initializer.
     */
    public static final OERDefinition.Builder ToBeSignedData;

    /**
     * SignedData ::= SEQUENCE {
     * hashId     HashAlgorithm,
     * tbsData    ToBeSignedData,
     * signer     SignerIdentifier,
     * signature  Signature
     * }
     */
    public static final OERDefinition.Builder SignedData = OERDefinition.seq(
        Ieee1609Dot2BaseTypes.HashAlgorithm.label("hashId"),
        OERDefinition.deferred(new ElementSupplier()
        {
            private Element built;

            public Element build()
            {
                synchronized (this)
                {
                    if (built == null)
                    {
                        built = ToBeSignedData.label("tbsData").build();
                    }
                    return built;
                }
            }
        }).label("tbsData"),
        SignerIdentifier.label("signer"),
        Ieee1609Dot2BaseTypes.Signature.label("signature")
    ).typeName("SignedData");

    /**
     * Ieee1609Dot2Content ::=  CHOICE {
     * unsecuredData             Opaque,
     * signedData                SignedData,
     * encryptedData             EncryptedData,
     * signedCertificateRequest  Opaque,
     * ...
     * }
     */
    public static final OERDefinition.Builder Ieee1609Dot2Content = OERDefinition.choice(

        Opaque.label("unsecuredData"),
        OERDefinition.deferred(new ElementSupplier()
        {
            private Element built;


            public Element build()
            {
                synchronized (this)
                {
                    if (built == null)
                    {
                        built = SignedData.label("signedData").mayRecurse(true).build();
                    }
                    return built;
                }
            }
            // new DeferredElementSupplier(SignedData.label("signedData")
        }).label("signedData").mayRecurse(true),
        EncryptedData.label("encryptedData"),
        Opaque.label("signedCertificateRequest"),
        OERDefinition.extension()).typeName("Ieee1609Dot2Content");

    public static final OERDefinition.Builder CounterSignature = OERDefinition.seq(
        Ieee1609Dot2BaseTypes.UINT8.label("protocolVersion"),
        Ieee1609Dot2Content.label("content")
    ).typeName("CounterSignature");
    /**
     * Ieee1609Dot2Data ::= SEQUENCE {
     * protocolVersion  Uint8(3),
     * content          Ieee1609Dot2Content
     * }
     */
    public static final OERDefinition.Builder Ieee1609Dot2Data = OERDefinition.seq(
        Ieee1609Dot2BaseTypes.UINT8.validSwitchValue(new ASN1Integer(3)).label("protocolVersion"),
        Ieee1609Dot2Content.label("content")).typeName("Ieee1609Dot2Data");
    /**
     * SignedDataPayload ::= SEQUENCE {
     * data         Ieee1609Dot2Data OPTIONAL,
     * extDataHash  HashedData OPTIONAL,
     * ...
     * } (WITH COMPONENTS {..., data PRESENT} |
     * WITH COMPONENTS {..., extDataHash PRESENT})
     */
    public static final OERDefinition.Builder SignedDataPayload = OERDefinition.seq(
        OERDefinition.optional(
            Ieee1609Dot2Data.label("data"),
            HashedData.label("extDataHash")),
        OERDefinition.extension()
    ).typeName("SignedDataPayload");

    static
    {
        /*
         * ToBeSignedData ::= SEQUENCE {
         *     payload     SignedDataPayload,
         *     headerInfo  HeaderInfo
         *   }
         */
        ToBeSignedData = OERDefinition.seq(
            SignedDataPayload.label("payload"),
            HeaderInfo.label("headerInfo")
        ).typeName("ToBeSignedData");
    }
}
