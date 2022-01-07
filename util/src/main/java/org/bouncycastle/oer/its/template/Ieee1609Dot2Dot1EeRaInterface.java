package org.bouncycastle.oer.its.template;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.oer.OERDefinition;

public class Ieee1609Dot2Dot1EeRaInterface
{

    /**
     * ButterflyExpansion ::= CHOICE {
     * aes128      OCTET STRING (SIZE(16)),
     * ...
     * }
     */
    public static final OERDefinition.Builder ButterflyExpansion = OERDefinition.choice(
        OERDefinition.octets(16).label("aes128"),
        OERDefinition.extension()
    ).label("ButterflyExpansion");


    /**
     * ButterflyParamsOriginal ::= SEQUENCE {
     * signingExpansion     ButterflyExpansion,
     * encryptionKey        PublicEncryptionKey,
     * encryptionExpansion  ButterflyExpansion
     * }
     */
    public static final OERDefinition.Builder ButterflyParamsOriginal = OERDefinition.seq(
        ButterflyExpansion.labelPrefix("signingExpansion"),
        Ieee1609Dot2BaseTypes.PublicEncryptionKey.labelPrefix("encryptionKey"),
        ButterflyExpansion.labelPrefix("encryptionExpansion")
    ).label("ButterflyParamsOriginal");


    /**
     * AdditionalParams ::= CHOICE {
     * original        ButterflyParamsOriginal,
     * unified         ButterflyExpansion,
     * compactUnified  ButterflyExpansion,
     * encryptionKey   PublicEncryptionKey,
     * ...
     * }
     */
    public static final OERDefinition.Builder AdditionalParams = OERDefinition.choice(
        ButterflyParamsOriginal.labelPrefix("original"),
        ButterflyExpansion.labelPrefix("unified"),
        ButterflyExpansion.labelPrefix("compactUnified"),
        Ieee1609Dot2BaseTypes.PublicEncryptionKey.labelPrefix("encryptionKey"),
        OERDefinition.extension()
    ).label("AdditionalParams");

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
    public static final OERDefinition.Builder EeRaCertRequest = OERDefinition.seq(
        Ieee1609Dot2BaseTypes.UINT8.labelPrefix("version").defaultValue(new ASN1Integer(2)),
        Ieee1609Dot2BaseTypes.Time32.labelPrefix("generationTime"),
        IEEE1609dot2.CertificateType.labelPrefix("type"),
        IEEE1609dot2.ToBeSignedCertificate.labelPrefix("tbsCert"),
        OERDefinition.optional(AdditionalParams.labelPrefix("additionalParams")),
        OERDefinition.extension()
    ).label("EeRaCertRequest");


}
