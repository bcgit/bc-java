package org.bouncycastle.oer.its.template.ieee1609dot2dot1;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;
import org.bouncycastle.oer.its.template.ieee1609dot2.basetypes.Ieee1609Dot2BaseTypes;

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
    ).typeName("ButterflyExpansion");


    /**
     * ButterflyParamsOriginal ::= SEQUENCE {
     * signingExpansion     ButterflyExpansion,
     * encryptionKey        PublicEncryptionKey,
     * encryptionExpansion  ButterflyExpansion
     * }
     */
    public static final OERDefinition.Builder ButterflyParamsOriginal = OERDefinition.seq(
        ButterflyExpansion.label("signingExpansion"),
        Ieee1609Dot2BaseTypes.PublicEncryptionKey.label("encryptionKey"),
        ButterflyExpansion.label("encryptionExpansion")
    ).typeName("ButterflyParamsOriginal");


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
        ButterflyParamsOriginal.label("original"),
        ButterflyExpansion.label("unified"),
        ButterflyExpansion.label("compactUnified"),
        Ieee1609Dot2BaseTypes.PublicEncryptionKey.label("encryptionKey"),
        OERDefinition.extension()
    ).typeName("AdditionalParams");

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
        Ieee1609Dot2BaseTypes.UINT8.label("version").validSwitchValue(new ASN1Integer(2)),
        Ieee1609Dot2BaseTypes.Time32.label("generationTime"),
        IEEE1609dot2.CertificateType.label("type"),
        IEEE1609dot2.ToBeSignedCertificate.label("tbsCert"),
        OERDefinition.optional(AdditionalParams.label("additionalParams")),
        OERDefinition.extension()
    ).typeName("EeRaCertRequest");


}
